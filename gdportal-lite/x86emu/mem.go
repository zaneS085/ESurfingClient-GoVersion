package x86emu

import (
	"encoding/binary"
	"fmt"
)

const (
	StackBase = 0x00100000
	StackSize = 0x00040000 // 256 KB
	InitESP   = 0x0013F000

	HeapBase    = 0x02000000
	HeapMaxSize = 0x00800000 // 8 MB max arena

	Ws2Base  = 0x7FE00000
	Ws2Size  = 0x00001000
	StubBase = 0x7FE10000
	StubSize = 0x00010000

	SysBase = 0x7FF00000
	SysSize = 0x00004000

	TEBAddr     = SysBase + 0x0000
	PEBAddr     = SysBase + 0x1000
	CtxPageAddr = SysBase + 0x2000
	FakeObjAddr = CtxPageAddr + 0x0040

	HaltAddr = 0x7FFFFFF0
)

const heapMagic uint32 = 0x48454150

// Mem 为纯 Go 32 位平坦虚拟地址空间（零 unsafe、零 host 指针依赖，完全可移植）
type Mem struct {
	imgBase     uint32
	imgLen      uint32
	img         []byte
	stack       []byte
	heapLen     uint32
	heap        []byte
	heapTop     uint32
	freeMap     map[uint32][]uint32 // aligned size -> free ptrs
	ws2         []byte
	sys         []byte
	codeStart   uint32
	codeEnd     uint32
	onCodeWrite func()
}

func NewMem(imageBase, imageSize uint32) *Mem {
	if imageSize < 0x1000 {
		imageSize = 0x1000
	}
	return &Mem{
		imgBase: imageBase,
		imgLen:  imageSize,
		img:     make([]byte, imageSize),
		stack:   make([]byte, StackSize),
		heapLen: 0x40000,
		heap:    make([]byte, 0x40000), // 初始 256 KB，按需倍增到 HeapMaxSize
		heapTop: 16,
		freeMap: make(map[uint32][]uint32),
		ws2:     make([]byte, Ws2Size),
		sys:     make([]byte, SysSize),
	}
}

func (m *Mem) ImageSlice() []byte { return m.img }
func (m *Mem) Ws2Slice() []byte   { return m.ws2 }
func (m *Mem) SysSlice() []byte   { return m.sys }

func (m *Mem) SetCodeWatch(start, end uint32, fn func()) {
	m.codeStart = start
	m.codeEnd = end
	m.onCodeWrite = fn
}

func (m *Mem) checkCodeRange(addr, size uint32) {
	if m.onCodeWrite != nil && addr < m.codeEnd && uint64(addr)+uint64(size) > uint64(m.codeStart) {
		m.onCodeWrite()
	}
}

// translate 把 32 位虚拟地址映射到对应后台切片及偏移
func (m *Mem) translate(addr uint32, n uint32) ([]byte, uint32, bool) {
	if n == 0 {
		return nil, 0, false
	}
	if addr >= m.imgBase && addr < m.imgBase+uint32(len(m.img)) {
		off := addr - m.imgBase
		if uint64(off)+uint64(n) <= uint64(len(m.img)) {
			return m.img, off, true
		}
		return nil, 0, false
	}
	if addr >= StackBase && addr < StackBase+uint32(len(m.stack)) {
		off := addr - StackBase
		if uint64(off)+uint64(n) <= uint64(len(m.stack)) {
			return m.stack, off, true
		}
		return nil, 0, false
	}
	if addr >= HeapBase && addr < HeapBase+uint32(len(m.heap)) {
		off := addr - HeapBase
		if uint64(off)+uint64(n) <= uint64(len(m.heap)) {
			return m.heap, off, true
		}
		return nil, 0, false
	}
	if addr >= SysBase && addr < SysBase+uint32(len(m.sys)) {
		off := addr - SysBase
		if uint64(off)+uint64(n) <= uint64(len(m.sys)) {
			return m.sys, off, true
		}
		return nil, 0, false
	}
	if addr >= Ws2Base && addr < Ws2Base+uint32(len(m.ws2)) {
		off := addr - Ws2Base
		if uint64(off)+uint64(n) <= uint64(len(m.ws2)) {
			return m.ws2, off, true
		}
		return nil, 0, false
	}
	return nil, 0, false
}

func (m *Mem) fastRead8(addr uint32) (byte, bool) {
	if off := addr - StackBase; off < StackSize {
		return m.stack[off], true
	}
	if off := addr - m.imgBase; off < m.imgLen {
		return m.img[off], true
	}
	if off := addr - HeapBase; off < m.heapLen {
		return m.heap[off], true
	}
	return 0, false
}

func (m *Mem) fastRead16(addr uint32) (uint16, bool) {
	if off := addr - StackBase; off <= StackSize-2 {
		b := m.stack[off : off+2]
		return uint16(b[0]) | uint16(b[1])<<8, true
	}
	if off := addr - m.imgBase; off <= m.imgLen-2 {
		b := m.img[off : off+2]
		return uint16(b[0]) | uint16(b[1])<<8, true
	}
	if off := addr - HeapBase; off <= m.heapLen-2 {
		b := m.heap[off : off+2]
		return uint16(b[0]) | uint16(b[1])<<8, true
	}
	return 0, false
}

func (m *Mem) fastRead32(addr uint32) (uint32, bool) {
	if off := addr - StackBase; off <= StackSize-4 {
		b := m.stack[off : off+4]
		return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
	}
	if off := addr - m.imgBase; off <= m.imgLen-4 {
		b := m.img[off : off+4]
		return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
	}
	if off := addr - HeapBase; off <= m.heapLen-4 {
		b := m.heap[off : off+4]
		return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
	}
	return 0, false
}

func (m *Mem) fastWrite8(addr uint32, v byte) bool {
	if off := addr - StackBase; off < StackSize {
		m.stack[off] = v
		return true
	}
	if off := addr - HeapBase; off < m.heapLen {
		m.heap[off] = v
		return true
	}
	if off := addr - m.imgBase; off < m.imgLen {
		m.img[off] = v
		if m.onCodeWrite != nil && addr-m.codeStart < m.codeEnd-m.codeStart {
			m.onCodeWrite()
		}
		return true
	}
	return false
}

func (m *Mem) fastWrite32(addr uint32, v uint32) bool {
	if off := addr - StackBase; off <= StackSize-4 {
		b := m.stack[off : off+4]
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
		return true
	}
	if off := addr - HeapBase; off <= m.heapLen-4 {
		b := m.heap[off : off+4]
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
		return true
	}
	if off := addr - m.imgBase; off <= m.imgLen-4 {
		b := m.img[off : off+4]
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
		m.checkCodeRange(addr, 4)
		return true
	}
	return false
}

func (m *Mem) Read8(addr uint32) (byte, error) {
	if v, ok := m.fastRead8(addr); ok {
		return v, nil
	}
	buf, off, ok := m.translate(addr, 1)
	if !ok {
		return 0, fmt.Errorf("unmapped read8 @0x%08x", addr)
	}
	return buf[off], nil
}

func (m *Mem) Read16(addr uint32) (uint16, error) {
	if v, ok := m.fastRead16(addr); ok {
		return v, nil
	}
	buf, off, ok := m.translate(addr, 2)
	if !ok {
		return 0, fmt.Errorf("unmapped read16 @0x%08x", addr)
	}
	return binary.LittleEndian.Uint16(buf[off : off+2]), nil
}

func (m *Mem) Read32(addr uint32) (uint32, error) {
	if v, ok := m.fastRead32(addr); ok {
		return v, nil
	}
	buf, off, ok := m.translate(addr, 4)
	if !ok {
		return 0, fmt.Errorf("unmapped read32 @0x%08x", addr)
	}
	return binary.LittleEndian.Uint32(buf[off : off+4]), nil
}

func (m *Mem) ReadBytes(addr uint32, n uint32) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	buf, off, ok := m.translate(addr, n)
	if !ok {
		return nil, fmt.Errorf("unmapped read%d @0x%08x", n, addr)
	}
	out := make([]byte, n)
	copy(out, buf[off:off+n])
	return out, nil
}

func (m *Mem) Write8(addr uint32, v byte) error {
	if m.fastWrite8(addr, v) {
		return nil
	}
	buf, off, ok := m.translate(addr, 1)
	if !ok {
		return fmt.Errorf("unmapped write8 @0x%08x", addr)
	}
	buf[off] = v
	return nil
}

func (m *Mem) Write16(addr uint32, v uint16) error {
	if off := addr - StackBase; off <= StackSize-2 {
		b := m.stack[off : off+2]
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		return nil
	}
	if off := addr - HeapBase; off <= m.heapLen-2 {
		b := m.heap[off : off+2]
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		return nil
	}
	buf, off, ok := m.translate(addr, 2)
	if !ok {
		return fmt.Errorf("unmapped write16 @0x%08x", addr)
	}
	binary.LittleEndian.PutUint16(buf[off:off+2], v)
	m.checkCodeRange(addr, 2)
	return nil
}

func (m *Mem) Write32(addr uint32, v uint32) error {
	if m.fastWrite32(addr, v) {
		return nil
	}
	buf, off, ok := m.translate(addr, 4)
	if !ok {
		return fmt.Errorf("unmapped write32 @0x%08x", addr)
	}
	binary.LittleEndian.PutUint32(buf[off:off+4], v)
	return nil
}

func (m *Mem) WriteBytes(addr uint32, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	buf, off, ok := m.translate(addr, uint32(len(data)))
	if !ok {
		return fmt.Errorf("unmapped write%d @0x%08x", len(data), addr)
	}
	copy(buf[off:off+uint32(len(data))], data)
	m.checkCodeRange(addr, uint32(len(data)))
	return nil
}

func (m *Mem) Fill(addr, n uint32, val byte) error {
	if n == 0 {
		return nil
	}
	buf, off, ok := m.translate(addr, n)
	if !ok {
		return fmt.Errorf("unmapped fill%d @0x%08x", n, addr)
	}
	s := buf[off : off+n]
	for i := range s {
		s[i] = val
	}
	m.checkCodeRange(addr, n)
	return nil
}

func (m *Mem) ReadCStr(addr uint32, maxLen uint32) string {
	if addr == 0 {
		return ""
	}
	out := make([]byte, 0, 64)
	for i := uint32(0); i < maxLen; i++ {
		b, err := m.Read8(addr + i)
		if err != nil || b == 0 {
			break
		}
		out = append(out, b)
	}
	return string(out)
}

func (m *Mem) ReadWStrASCII(addr uint32, maxChars uint32) string {
	if addr == 0 {
		return ""
	}
	out := make([]byte, 0, 64)
	for i := uint32(0); i < maxChars; i++ {
		w, err := m.Read16(addr + i*2)
		if err != nil || w == 0 {
			break
		}
		if w < 128 {
			out = append(out, byte(w))
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}

func (m *Mem) WriteCStr(addr uint32, s string) error {
	if err := m.WriteBytes(addr, []byte(s)); err != nil {
		return err
	}
	return m.Write8(addr+uint32(len(s)), 0)
}

// Alloc 在 VM 堆区分配 16 字节对齐块 (前置 8 字节元信息 [size, magic])
func (m *Mem) Alloc(size uint32, zero bool) uint32 {
	if size == 0 {
		size = 16
	}
	aligned := (size + 15) &^ 15
	if q := m.freeMap[aligned]; len(q) > 0 {
		ptr := q[len(q)-1]
		m.freeMap[aligned] = q[:len(q)-1]
		if zero {
			_ = m.Fill(ptr, aligned, 0)
		}
		return ptr
	}
	need := m.heapTop + 8 + aligned + 8 // 前置 8B 头 + 冗余尾保护
	if need > HeapMaxSize {
		return 0
	}
	if need > uint32(len(m.heap)) {
		newCap := uint32(len(m.heap)) * 2
		for newCap < need {
			newCap *= 2
		}
		if newCap > HeapMaxSize {
			newCap = HeapMaxSize
		}
		nb := make([]byte, newCap)
		copy(nb, m.heap)
		m.heap = nb
		m.heapLen = newCap
	}
	hdrOff := m.heapTop
	ptr := HeapBase + hdrOff + 8
	binary.LittleEndian.PutUint32(m.heap[hdrOff:hdrOff+4], aligned)
	binary.LittleEndian.PutUint32(m.heap[hdrOff+4:hdrOff+8], heapMagic)
	m.heapTop += 8 + aligned
	if zero {
		_ = m.Fill(ptr, aligned, 0)
	}
	return ptr
}

func (m *Mem) blockSize(ptr uint32) (uint32, bool) {
	if ptr < HeapBase+8 || ptr >= HeapBase+m.heapTop {
		return 0, false
	}
	off := ptr - HeapBase - 8
	sz := binary.LittleEndian.Uint32(m.heap[off : off+4])
	mag := binary.LittleEndian.Uint32(m.heap[off+4 : off+8])
	if mag != heapMagic {
		return 0, false
	}
	return sz, true
}

func (m *Mem) Free(ptr uint32) {
	if ptr == 0 {
		return
	}
	sz, ok := m.blockSize(ptr)
	if !ok {
		return
	}
	m.freeMap[sz] = append(m.freeMap[sz], ptr)
}

func (m *Mem) Realloc(ptr, newSize uint32) uint32 {
	if ptr == 0 {
		return m.Alloc(newSize, false)
	}
	if newSize == 0 {
		m.Free(ptr)
		return 0
	}
	oldSz, ok := m.blockSize(ptr)
	if !ok {
		return m.Alloc(newSize, false)
	}
	if newSize <= oldSz {
		return ptr
	}
	np := m.Alloc(newSize, false)
	if np == 0 {
		return 0
	}
	if b, err := m.ReadBytes(ptr, oldSz); err == nil {
		_ = m.WriteBytes(np, b)
	}
	m.Free(ptr)
	return np
}

func (m *Mem) AllocCStr(s string) uint32 {
	p := m.Alloc(uint32(len(s))+16, true)
	if p != 0 {
		_ = m.WriteCStr(p, s)
	}
	return p
}
