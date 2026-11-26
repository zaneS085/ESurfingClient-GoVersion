package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"math"
	"syscall"
	"unsafe"
)

var (
	modUser32Icon            = syscall.NewLazyDLL("user32.dll")
	procCreateIconFromResEx  = modUser32Icon.NewProc("CreateIconFromResourceEx")
	procDestroyIcon          = modUser32Icon.NewProc("DestroyIcon")
)

// buildAppICO 生成 32x32 32-bit ARGB ICO 图像 (现代 VS Code Cobalt 几何校园网信号徽标)
func buildAppICO() []byte {
	const w, h = 32, 32
	img := image.NewNRGBA(image.Rect(0, 0, w, h))

	bg := color.NRGBA{0x00, 0x78, 0xD4, 0xFF}      // VS Code Accent Blue
	bgHi := color.NRGBA{0x18, 0x90, 0xEB, 0xFF}    // Subtle top highlight
	fg := color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}      // Crisp white mark

	inRoundedBox := func(x, y float64, r float64) bool {
		px := math.Abs(x-15.5) - (13.5 - r)
		py := math.Abs(y-15.5) - (13.5 - r)
		if px <= 0 || py <= 0 {
			return math.Abs(x-15.5) <= 13.5 && math.Abs(y-15.5) <= 13.5
		}
		return px*px+py*py <= r*r
	}

	distSeg := func(px, py, ax, ay, bx, by float64) float64 {
		vx, vy := bx-ax, by-ay
		wx, wy := px-ax, py-ay
		c1 := vx*wx + vy*wy
		if c1 <= 0 {
			return math.Hypot(px-ax, py-ay)
		}
		c2 := vx*vx + vy*vy
		if c2 <= c1 {
			return math.Hypot(px-bx, py-by)
		}
		b := c1 / c2
		return math.Hypot(px-(ax+b*vx), py-(ay+b*vy))
	}

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			fx, fy := float64(x), float64(y)
			if !inRoundedBox(fx, fy, 6.0) {
				continue
			}
			c := bg
			if y < 14 {
				c = bgHi
			}
			// 几何网关信号桥徽标: 下方中心节点 + 两条对称信号弧 + 中心节点高亮
			cx, cy := 15.5, 22.5
			r := math.Hypot(fx-cx, fy-cy)
			ang := math.Atan2(cy-fy, fx-cx) // upward = pi/2
			inArc := ang >= math.Pi*0.22 && ang <= math.Pi*0.78 &&
				((math.Abs(r-7.2) <= 1.25) || (math.Abs(r-12.0) <= 1.25))
			inStem := r <= 2.35 || distSeg(fx, fy, cx, cy, cx, 10.5) <= 1.25 && fy <= cy
			if inArc || inStem {
				c = fg
			}
			img.SetNRGBA(x, y, c)
		}
	}

	// 组装标准 ICO (ICONDIR + ICONDIRENTRY + BITMAPINFOHEADER + BGRA pixels bottom-up + AND mask)
	var dib bytes.Buffer
	_ = binary.Write(&dib, binary.LittleEndian, uint32(40))     // biSize
	_ = binary.Write(&dib, binary.LittleEndian, int32(w))       // biWidth
	_ = binary.Write(&dib, binary.LittleEndian, int32(h*2))     // biHeight (XOR + AND)
	_ = binary.Write(&dib, binary.LittleEndian, uint16(1))      // biPlanes
	_ = binary.Write(&dib, binary.LittleEndian, uint16(32))     // biBitCount
	_ = binary.Write(&dib, binary.LittleEndian, uint32(0))      // biCompression (BI_RGB)
	_ = binary.Write(&dib, binary.LittleEndian, uint32(w*h*4))  // biSizeImage
	_ = binary.Write(&dib, binary.LittleEndian, int32(0))
	_ = binary.Write(&dib, binary.LittleEndian, int32(0))
	_ = binary.Write(&dib, binary.LittleEndian, uint32(0))
	_ = binary.Write(&dib, binary.LittleEndian, uint32(0))

	// bottom-up BGRA
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(x, y)
			dib.WriteByte(c.B)
			dib.WriteByte(c.G)
			dib.WriteByte(c.R)
			dib.WriteByte(c.A)
		}
	}
	// AND mask (32x32 bits = 128 bytes zeros since alpha channel handles transparency)
	dib.Write(make([]byte, (w/8)*h))

	dibBytes := dib.Bytes()
	var ico bytes.Buffer
	_ = binary.Write(&ico, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&ico, binary.LittleEndian, uint16(1)) // type=1 (ICO)
	_ = binary.Write(&ico, binary.LittleEndian, uint16(1)) // count=1
	ico.WriteByte(w)
	ico.WriteByte(h)
	ico.WriteByte(0)
	ico.WriteByte(0)
	_ = binary.Write(&ico, binary.LittleEndian, uint16(1))
	_ = binary.Write(&ico, binary.LittleEndian, uint16(32))
	_ = binary.Write(&ico, binary.LittleEndian, uint32(len(dibBytes)))
	_ = binary.Write(&ico, binary.LittleEndian, uint32(22))
	ico.Write(dibBytes)
	return ico.Bytes()
}

func createAppHICON() uintptr {
	ico := buildAppICO()
	if len(ico) <= 22 {
		return 0
	}
	dib := ico[22:]
	h, _, _ := procCreateIconFromResEx.Call(
		uintptr(unsafe.Pointer(&dib[0])),
		uintptr(len(dib)),
		1,          // fIcon = TRUE
		0x00030000, // dwVer
		32, 32,
		0, // LR_DEFAULTCOLOR
	)
	return h
}
