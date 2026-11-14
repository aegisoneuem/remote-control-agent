// Package video turns captured screens into an H.264 stream for a WebRTC video track, for
// smooth full-motion remote control (30 fps) at a fraction of the bandwidth of JPEG tiles.
//
// The encoder runs FFmpeg (libx264, or a hardware encoder) as a child process: raw RGBA frames
// go to its stdin, an Annex-B H.264 elementary stream comes back on stdout and is split into
// access units on the AUD NAL units x264 is told to emit. When FFmpeg is not available the agent
// keeps using JPEG tiles, so video is an optimisation, never a dependency.
//
// Licensing note for production: FFmpeg with libx264 is GPL. A shipped product should use the
// Windows Media Foundation H.264 encoder (built into Windows, hardware accelerated) or a
// separately downloaded OpenH264; this package keeps the encoder behind one small interface so
// it can be swapped.
package video

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"image"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
)

// Encoder takes RGBA frames and returns H.264 access units (Annex B), possibly with a delay of
// a frame or two.
type Encoder struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	w, h   int
	aus    chan []byte
	mu     sync.Mutex
	closed bool
	errMu  sync.Mutex
	err    error
}

// FindFFmpeg returns the FFmpeg executable: an explicit path, one next to the agent, or PATH.
func FindFFmpeg(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}
	name := "ffmpeg"
	if runtime.GOOS == "windows" {
		name = "ffmpeg.exe"
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return exec.LookPath(name)
}

// Start launches an encoder for w x h frames (both made even) at fps, a keyframe every
// keyEvery frames, target bitrate kbps.
func Start(ffmpeg string, w, h, fps, keyEvery, kbps int) (*Encoder, error) {
	w, h = w&^1, h&^1
	if w < 16 || h < 16 {
		return nil, errors.New("screen too small for video")
	}
	args := []string{"-hide_banner", "-loglevel", "error",
		"-f", "rawvideo", "-pix_fmt", "rgba", "-s", fmt.Sprintf("%dx%d", w, h), "-r", strconv.Itoa(fps), "-i", "-",
		// cap very large desktops at 1920 wide; input coordinates are fractions, so scaling is safe
		"-vf", "scale='min(1920,iw)':-2:flags=bilinear,format=yuv420p",
		"-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline", "-level", "4.1",
		"-g", strconv.Itoa(keyEvery), "-bf", "0", "-b:v", strconv.Itoa(kbps) + "k", "-maxrate", strconv.Itoa(kbps*2) + "k", "-bufsize", strconv.Itoa(kbps) + "k",
		"-x264-params", "aud=1:repeat-headers=1:sliced-threads=1",
		"-f", "h264", "-"}
	cmd := exec.Command(ffmpeg, args...)
	hideWindow(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ffmpeg: %w", err)
	}
	e := &Encoder{cmd: cmd, stdin: stdin, w: w, h: h, aus: make(chan []byte, 8)}
	go e.read(stdout, &stderr)
	return e, nil
}

func (e *Encoder) Size() (int, int) { return e.w, e.h }

// read splits the byte stream at access unit delimiters (00 00 00 01 09).
func (e *Encoder) read(r io.Reader, stderr *bytes.Buffer) {
	br := bufio.NewReaderSize(r, 1<<20)
	aud := []byte{0, 0, 0, 1, 9}
	var cur []byte
	buf := make([]byte, 256<<10)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			cur = append(cur, buf[:n]...)
			for {
				// the stream starts with an AUD; look for the next one after it
				i := bytes.Index(cur[min(len(cur), 1):], aud)
				if i < 0 {
					break
				}
				i++ // index into cur
				au := cur[:i]
				cur = append([]byte(nil), cur[i:]...)
				if len(au) > len(aud) {
					select {
					case e.aus <- au:
					default: // the sender is behind; drop rather than build latency
					}
				}
			}
		}
		if err != nil {
			if len(cur) > len(aud) {
				select {
				case e.aus <- cur:
				default:
				}
			}
			e.errMu.Lock()
			if e.err == nil {
				e.err = fmt.Errorf("encoder stopped: %v %s", err, bytes.TrimSpace(stderr.Bytes()))
			}
			e.errMu.Unlock()
			close(e.aus)
			return
		}
	}
}

// Err reports why the encoder stopped, if it did.
func (e *Encoder) Err() error { e.errMu.Lock(); defer e.errMu.Unlock(); return e.err }

// Frames returns the access units as they come out of the encoder.
func (e *Encoder) Frames() <-chan []byte { return e.aus }

// Push sends one frame. img must be at least the encoder's size; extra pixels are cropped.
func (e *Encoder) Push(img *image.RGBA) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("encoder closed")
	}
	b := img.Bounds()
	if b.Dx() < e.w || b.Dy() < e.h {
		return errors.New("frame smaller than the encoder")
	}
	if b.Dx() == e.w && img.Stride == e.w*4 {
		_, err := e.stdin.Write(img.Pix[:e.w*e.h*4])
		return err
	}
	for y := 0; y < e.h; y++ {
		o := y * img.Stride
		if _, err := e.stdin.Write(img.Pix[o : o+e.w*4]); err != nil {
			return err
		}
	}
	return nil
}

func (e *Encoder) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	_ = e.stdin.Close()
	e.mu.Unlock()
	if e.cmd.Process != nil {
		_ = e.cmd.Process.Kill()
	}
	_ = e.cmd.Wait()
}
