//go:build windows

package platform

// DXGI Desktop Duplication: the GPU hands over the composed desktop, which is faster than GDI
// BitBlt at high resolutions and frame rates. It is opt-in (-capture dxgi) and any failure
// (no D3D11, secure desktop, mode change, remote session without a GPU) falls back to GDI.
//
// COM is called through the vtables directly. Indices (0-2 are IUnknown):
//   IDXGIDevice::GetAdapter 7 · IDXGIAdapter::EnumOutputs 7 · IDXGIOutput1::DuplicateOutput 22
//   IDXGIOutputDuplication: GetDesc 7, AcquireNextFrame 8, ReleaseFrame 14
//   ID3D11Device::CreateTexture2D 5 · ID3D11DeviceContext: Map 14, Unmap 15, CopyResource 47

import (
	"errors"
	"fmt"
	"image"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	d3d11              = windows.NewLazySystemDLL("d3d11.dll")
	pD3D11CreateDevice = d3d11.NewProc("D3D11CreateDevice")

	iidIDXGIDevice     = windows.GUID{Data1: 0x54ec77fa, Data2: 0x1377, Data3: 0x44e6, Data4: [8]byte{0x8c, 0x32, 0x88, 0xfd, 0x5f, 0x44, 0xc8, 0x4c}}
	iidIDXGIOutput1    = windows.GUID{Data1: 0x00cddea8, Data2: 0x939b, Data3: 0x4b83, Data4: [8]byte{0xa3, 0x40, 0xa6, 0x85, 0x22, 0x66, 0x66, 0xcc}}
	iidID3D11Texture2D = windows.GUID{Data1: 0x6f15aaf2, Data2: 0xd208, Data3: 0x4e89, Data4: [8]byte{0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c}}
)

const (
	dxgiErrWaitTimeout = 0x887A0027
	dxgiErrAccessLost  = 0x887A0026
	ptr                = unsafe.Sizeof(uintptr(0))
)

type comObj unsafe.Pointer

// vcall calls method idx on a COM object.
func vcall(o comObj, idx uintptr, args ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(unsafe.Pointer(o))
	fn := *(*uintptr)(unsafe.Add(vtbl, idx*ptr))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)...)
	return r
}

func release(o comObj) {
	if o != nil {
		vcall(o, 2)
	}
}

type texDesc struct {
	Width, Height, MipLevels, ArraySize, Format, SampleCount, SampleQuality, Usage, BindFlags, CPUAccessFlags, MiscFlags uint32
}

type mapped struct {
	Data       unsafe.Pointer
	RowPitch   uint32
	DepthPitch uint32
}

type dxgiCapture struct {
	dev, ctx, dup, staging comObj
	w, h                   int
	last                   *image.RGBA
}

func hr(r uintptr, what string) error {
	if int32(r) < 0 {
		return fmt.Errorf("%s: HRESULT 0x%08X", what, uint32(r))
	}
	return nil
}

func newDXGI() (*dxgiCapture, error) {
	if err := pD3D11CreateDevice.Find(); err != nil {
		return nil, err
	}
	d := &dxgiCapture{}
	var dev, ctx unsafe.Pointer
	var fl uint32
	const driverHardware, bgraSupport, sdkVersion = 1, 0x20, 7
	r, _, _ := pD3D11CreateDevice.Call(0, driverHardware, 0, bgraSupport, 0, 0, sdkVersion,
		uintptr(unsafe.Pointer(&dev)), uintptr(unsafe.Pointer(&fl)), uintptr(unsafe.Pointer(&ctx)))
	if err := hr(r, "D3D11CreateDevice"); err != nil {
		return nil, err
	}
	d.dev, d.ctx = comObj(dev), comObj(ctx)
	var dxdev, adapter, output, output1, dup unsafe.Pointer
	if err := hr(vcall(d.dev, 0, uintptr(unsafe.Pointer(&iidIDXGIDevice)), uintptr(unsafe.Pointer(&dxdev))), "QueryInterface IDXGIDevice"); err != nil {
		d.close()
		return nil, err
	}
	defer release(comObj(dxdev))
	if err := hr(vcall(comObj(dxdev), 7, uintptr(unsafe.Pointer(&adapter))), "GetAdapter"); err != nil {
		d.close()
		return nil, err
	}
	defer release(comObj(adapter))
	if err := hr(vcall(comObj(adapter), 7, 0, uintptr(unsafe.Pointer(&output))), "EnumOutputs"); err != nil {
		d.close()
		return nil, err
	}
	defer release(comObj(output))
	if err := hr(vcall(comObj(output), 0, uintptr(unsafe.Pointer(&iidIDXGIOutput1)), uintptr(unsafe.Pointer(&output1))), "QueryInterface IDXGIOutput1"); err != nil {
		d.close()
		return nil, err
	}
	defer release(comObj(output1))
	if err := hr(vcall(comObj(output1), 22, uintptr(unsafe.Pointer(d.dev)), uintptr(unsafe.Pointer(&dup))), "DuplicateOutput"); err != nil {
		d.close()
		return nil, err
	}
	d.dup = comObj(dup)
	var desc [36]byte // DXGI_OUTDUPL_DESC: ModeDesc (Width, Height first), Rotation, DesktopImageInSystemMemory
	vcall(d.dup, 7, uintptr(unsafe.Pointer(&desc[0])))
	d.w, d.h = int(*(*uint32)(unsafe.Pointer(&desc[0]))), int(*(*uint32)(unsafe.Pointer(&desc[4])))
	if d.w <= 0 || d.h <= 0 {
		d.close()
		return nil, errors.New("duplication reports no size")
	}
	td := texDesc{Width: uint32(d.w), Height: uint32(d.h), MipLevels: 1, ArraySize: 1, Format: 87 /* B8G8R8A8_UNORM */, SampleCount: 1,
		Usage: 3 /* STAGING */, CPUAccessFlags: 0x20000 /* READ */}
	var st unsafe.Pointer
	if err := hr(vcall(d.dev, 5, uintptr(unsafe.Pointer(&td)), 0, uintptr(unsafe.Pointer(&st))), "CreateTexture2D"); err != nil {
		d.close()
		return nil, err
	}
	d.staging = comObj(st)
	return d, nil
}

// frame returns the desktop image. When nothing changed it returns the previous frame.
func (d *dxgiCapture) frame() (*image.RGBA, error) {
	var info [64]byte // DXGI_OUTDUPL_FRAME_INFO (48 bytes)
	var res unsafe.Pointer
	r := vcall(d.dup, 8, 50, uintptr(unsafe.Pointer(&info[0])), uintptr(unsafe.Pointer(&res)))
	if uint32(r) == dxgiErrWaitTimeout {
		if d.last != nil {
			return d.last, nil
		}
		return nil, errors.New("no desktop frame yet")
	}
	if uint32(r) == dxgiErrAccessLost {
		return nil, errAccessLost
	}
	if err := hr(r, "AcquireNextFrame"); err != nil {
		return nil, err
	}
	defer vcall(d.dup, 14) // ReleaseFrame
	defer release(comObj(res))
	var tex unsafe.Pointer
	if err := hr(vcall(comObj(res), 0, uintptr(unsafe.Pointer(&iidID3D11Texture2D)), uintptr(unsafe.Pointer(&tex))), "QueryInterface ID3D11Texture2D"); err != nil {
		return nil, err
	}
	defer release(comObj(tex))
	vcall(d.ctx, 47, uintptr(unsafe.Pointer(d.staging)), uintptr(tex)) // CopyResource(dst, src)
	var m mapped
	if err := hr(vcall(d.ctx, 14, uintptr(unsafe.Pointer(d.staging)), 0, 1 /* MAP_READ */, 0, uintptr(unsafe.Pointer(&m))), "Map"); err != nil {
		return nil, err
	}
	img := image.NewRGBA(image.Rect(0, 0, d.w, d.h))
	for y := 0; y < d.h; y++ {
		src := unsafe.Slice((*byte)(unsafe.Add(m.Data, uintptr(y)*uintptr(m.RowPitch))), d.w*4)
		dst := img.Pix[y*img.Stride : y*img.Stride+d.w*4]
		for i := 0; i < len(src); i += 4 { // BGRA -> RGBA
			dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 255
		}
	}
	vcall(d.ctx, 15, uintptr(unsafe.Pointer(d.staging)), 0) // Unmap
	drawPointer(img)
	d.last = img
	return img, nil
}

var errAccessLost = errors.New("desktop duplication access lost (mode change or desktop switch)")

func (d *dxgiCapture) close() {
	release(d.staging)
	release(d.dup)
	release(d.ctx)
	release(d.dev)
	d.staging, d.dup, d.ctx, d.dev = nil, nil, nil, nil
}

// drawPointer paints a simple arrow at the cursor position: Desktop Duplication delivers the
// desktop without the mouse pointer.
func drawPointer(img *image.RGBA) {
	var ci cursorInfo
	ci.Size = uint32(unsafe.Sizeof(ci))
	if r, _, _ := pGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r == 0 || ci.Flags&cursorShowing == 0 {
		return
	}
	x0, y0 := int(ci.Pt.X), int(ci.Pt.Y)
	b := img.Bounds()
	set := func(x, y int, c byte) {
		if x >= b.Min.X && x < b.Max.X && y >= b.Min.Y && y < b.Max.Y {
			o := img.PixOffset(x, y)
			img.Pix[o], img.Pix[o+1], img.Pix[o+2], img.Pix[o+3] = c, c, c, 255
		}
	}
	for dy := 0; dy < 16; dy++ {
		for dx := 0; dx <= dy/2+1 && dx < 10; dx++ {
			edge := dx == 0 || dx == dy/2+1 || dy == 15
			c := byte(255)
			if edge {
				c = 0
			}
			set(x0+dx, y0+dy, c)
		}
	}
}
