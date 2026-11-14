package video

import (
	"image"
	"image/color"
	"testing"
	"time"
)

func TestEncoderProducesAccessUnits(t *testing.T) {
	ff, err := FindFFmpeg("")
	if err != nil {
		t.Skip("ffmpeg not installed")
	}
	e, err := Start(ff, 641, 361, 15, 15, 800) // odd sizes are cropped to even
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if w, h := e.Size(); w != 640 || h != 360 {
		t.Fatalf("size %dx%d", w, h)
	}
	img := image.NewRGBA(image.Rect(0, 0, 641, 361))
	go func() {
		for i := 0; i < 30; i++ {
			for x := 0; x < 641; x++ {
				img.Set(x, (i*7)%361, color.RGBA{uint8(i * 8), 200, 50, 255})
			}
			if e.Push(img) != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	got, idr := 0, false
	deadline := time.After(10 * time.Second)
	for got < 10 {
		select {
		case au, ok := <-e.Frames():
			if !ok {
				t.Fatalf("encoder stopped: %v", e.Err())
			}
			if au[4] != 9 {
				t.Fatalf("access unit does not start with an AUD: % x", au[:8])
			}
			for i := 0; i+4 < len(au); i++ {
				if au[i] == 0 && au[i+1] == 0 && au[i+2] == 1 && au[i+3]&0x1f == 5 {
					idr = true
				}
			}
			got++
		case <-deadline:
			t.Fatalf("only %d access units", got)
		}
	}
	if !idr {
		t.Fatal("no IDR frame in the first access units")
	}
}
