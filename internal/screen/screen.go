// Package screen turns captured frames into compact tile updates for the WebRTC "screen" data
// channel. Only tiles that changed since the last frame are JPEG-encoded and sent, so a still
// desktop costs almost no bandwidth.
//
// Wire format (all integers big endian):
//
//	frame start: 0x01 | u16 width | u16 height | u32 seq | u8 key (1 = full frame)
//	tile batch:  0x02 | u16 count | count x (u16 x | u16 y | u16 w | u16 h | u32 len | len bytes JPEG)
//	frame end:   0x03 | u32 seq
package screen

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/jpeg"
)

const (
	Tile     = 64
	maxBatch = 56 * 1024 // stay well under browser SCTP message limits
)

// Encoder remembers the previous frame so it can send only what changed.
type Encoder struct {
	prev    *image.RGBA
	seq     uint32
	Quality int
}

func NewEncoder() *Encoder { return &Encoder{Quality: 70} }

// Encode returns the messages for one frame. full forces every tile (a keyframe).
// It returns nil when nothing changed.
func (e *Encoder) Encode(img *image.RGBA, full bool) [][]byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if e.prev == nil || e.prev.Bounds() != b {
		full = true
	}
	var tiles []image.Rectangle
	for ty := 0; ty < h; ty += Tile {
		for tx := 0; tx < w; tx += Tile {
			r := image.Rect(tx, ty, min(tx+Tile, w), min(ty+Tile, h)).Add(b.Min)
			if full || changed(e.prev, img, r) {
				tiles = append(tiles, r)
			}
		}
	}
	// keep a copy as the reference for the next diff
	if e.prev == nil || e.prev.Bounds() != b {
		e.prev = image.NewRGBA(b)
	}
	copy(e.prev.Pix, img.Pix)
	if len(tiles) == 0 {
		return nil
	}
	e.seq++
	out := [][]byte{start(w, h, e.seq, full)}
	var batch bytes.Buffer
	count := 0
	flush := func() {
		if count == 0 {
			return
		}
		msg := make([]byte, 3, 3+batch.Len())
		msg[0] = 0x02
		binary.BigEndian.PutUint16(msg[1:], uint16(count))
		msg = append(msg, batch.Bytes()...)
		out = append(out, msg)
		batch.Reset()
		count = 0
	}
	var jb bytes.Buffer
	for _, r := range tiles {
		jb.Reset()
		if err := jpeg.Encode(&jb, img.SubImage(r), &jpeg.Options{Quality: e.Quality}); err != nil {
			continue
		}
		if batch.Len()+12+jb.Len() > maxBatch {
			flush()
		}
		var hdr [12]byte
		binary.BigEndian.PutUint16(hdr[0:], uint16(r.Min.X-b.Min.X))
		binary.BigEndian.PutUint16(hdr[2:], uint16(r.Min.Y-b.Min.Y))
		binary.BigEndian.PutUint16(hdr[4:], uint16(r.Dx()))
		binary.BigEndian.PutUint16(hdr[6:], uint16(r.Dy()))
		binary.BigEndian.PutUint32(hdr[8:], uint32(jb.Len()))
		batch.Write(hdr[:])
		batch.Write(jb.Bytes())
		count++
	}
	flush()
	end := make([]byte, 5)
	end[0] = 0x03
	binary.BigEndian.PutUint32(end[1:], e.seq)
	return append(out, end)
}

// Full encodes every tile without touching the diff reference. Used when one viewer needs a
// keyframe while the others keep receiving diffs.
func (e *Encoder) Full(img *image.RGBA) [][]byte {
	saved, seq := e.prev, e.seq
	e.prev = nil
	out := e.Encode(img, true)
	e.prev, e.seq = saved, seq
	if e.prev == nil {
		e.prev = image.NewRGBA(img.Bounds())
		copy(e.prev.Pix, img.Pix)
	}
	return out
}

func start(w, h int, seq uint32, key bool) []byte {
	m := make([]byte, 10)
	m[0] = 0x01
	binary.BigEndian.PutUint16(m[1:], uint16(w))
	binary.BigEndian.PutUint16(m[3:], uint16(h))
	binary.BigEndian.PutUint32(m[5:], seq)
	if key {
		m[9] = 1
	}
	return m
}

func changed(a, b *image.RGBA, r image.Rectangle) bool {
	if a == nil {
		return true
	}
	rowLen := r.Dx() * 4
	for y := r.Min.Y; y < r.Max.Y; y++ {
		i := b.PixOffset(r.Min.X, y)
		if !bytes.Equal(a.Pix[i:i+rowLen], b.Pix[i:i+rowLen]) {
			return true
		}
	}
	return false
}
