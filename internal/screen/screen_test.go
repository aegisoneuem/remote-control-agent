package screen

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
)

func decode(t *testing.T, msgs [][]byte, canvas *image.RGBA) (tiles int) {
	for _, m := range msgs {
		switch m[0] {
		case 1:
			if int(binary.BigEndian.Uint16(m[1:])) != canvas.Bounds().Dx() {
				t.Fatal("bad width")
			}
		case 2:
			n, off := int(binary.BigEndian.Uint16(m[1:])), 3
			for i := 0; i < n; i++ {
				x, y := int(binary.BigEndian.Uint16(m[off:])), int(binary.BigEndian.Uint16(m[off+2:]))
				l := int(binary.BigEndian.Uint32(m[off+8:]))
				img, err := jpeg.Decode(bytes.NewReader(m[off+12 : off+12+l]))
				if err != nil {
					t.Fatal(err)
				}
				b := img.Bounds()
				for yy := 0; yy < b.Dy(); yy++ {
					for xx := 0; xx < b.Dx(); xx++ {
						canvas.Set(x+xx, y+yy, img.At(b.Min.X+xx, b.Min.Y+yy))
					}
				}
				off += 12 + l
				tiles++
			}
			if len(m) > maxBatch+3 {
				t.Fatalf("batch too large: %d", len(m))
			}
		}
	}
	return
}

func TestDiffSendsOnlyChangedTiles(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 640, 360))
	for i := range img.Pix {
		img.Pix[i] = 200
	}
	e := NewEncoder()
	canvas := image.NewRGBA(img.Bounds())
	first := decode(t, e.Encode(img, false), canvas)
	if first != 10*6 {
		t.Fatalf("first frame should be full: %d tiles", first)
	}
	if e.Encode(img, false) != nil {
		t.Fatal("unchanged frame should send nothing")
	}
	img.Set(100, 100, color.RGBA{255, 0, 0, 255})
	if n := decode(t, e.Encode(img, false), canvas); n != 1 {
		t.Fatalf("one changed pixel should send one tile, got %d", n)
	}
	if n := decode(t, e.Full(img), canvas); n != 60 {
		t.Fatalf("keyframe should send all tiles, got %d", n)
	}
	if e.Encode(img, false) != nil {
		t.Fatal("Full must not disturb the diff reference")
	}
}
