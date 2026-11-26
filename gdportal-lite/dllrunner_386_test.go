//go:build windows && 386

package main

import (
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"
)

// 7. hexDecodeBuf 与 windowsBuild 验证 (legacy windows/386 原生回调)
func TestHexDecodeBufAndWindowsBuild(t *testing.T) {
	in := append([]byte(" \t48656c6c6f\r\n "), 0)
	blk := hexDecodeBuf(uintptr(unsafe.Pointer(&in[0])))
	if blk == 0 {
		t.Fatal("hexDecodeBuf returned 0")
	}
	defer k32Free(blk, 0)
	mem := unsafe.Slice((*byte)(unsafe.Pointer(blk)), 64)
	ln := binary.LittleEndian.Uint32(mem[4:8])
	dp := binary.LittleEndian.Uint32(mem[8:12])
	if ln != 5 || dp != uint32(blk+16) {
		t.Fatalf("statebuf header mismatch: ln=%d dp=0x%x blk=0x%x", ln, dp, blk)
	}
	if string(mem[16:21]) != "Hello" || mem[21] != 0 {
		t.Fatalf("decoded data mismatch: %x", mem[16:22])
	}

	bad := append([]byte("not-hex"), 0)
	if hexDecodeBuf(uintptr(unsafe.Pointer(&bad[0]))) != 0 {
		t.Fatal("invalid hex should return 0")
	}

	wb := windowsBuild()
	if !strings.HasPrefix(wb, "Windows ") || !strings.HasSuffix(wb, ",64 bit ") {
		t.Fatalf("unexpected windowsBuild: %q", wb)
	}
}

// 8. manualMap 必须只复制 SizeOfRawData，绝不能把紧邻节(.reloc)字节抄进 .data 的 .bss 零填充区
func TestManualMapPreservesBSSZeroing(t *testing.T) {
	pe := make([]byte, 0x800)
	pe[0], pe[1] = 'M', 'Z'
	const peOff = 0x80
	binary.LittleEndian.PutUint32(pe[0x3C:], peOff)
	copy(pe[peOff:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(pe[peOff+4:], 0x014C)
	binary.LittleEndian.PutUint16(pe[peOff+6:], 2)
	binary.LittleEndian.PutUint16(pe[peOff+20:], 0xE0)
	opt := peOff + 24
	binary.LittleEndian.PutUint16(pe[opt:], 0x010B)
	binary.LittleEndian.PutUint32(pe[opt+28:], 0x10000000)
	binary.LittleEndian.PutUint32(pe[opt+56:], 0x4000)
	binary.LittleEndian.PutUint32(pe[opt+60:], 0x400)
	sec0 := opt + 0xE0
	copy(pe[sec0:], ".data\x00\x00\x00")
	binary.LittleEndian.PutUint32(pe[sec0+8:], 0x400)
	binary.LittleEndian.PutUint32(pe[sec0+12:], 0x2000)
	binary.LittleEndian.PutUint32(pe[sec0+16:], 0x200)
	binary.LittleEndian.PutUint32(pe[sec0+20:], 0x400)
	sec1 := sec0 + 40
	copy(pe[sec1:], ".reloc\x00\x00")
	binary.LittleEndian.PutUint32(pe[sec1+8:], 0x200)
	binary.LittleEndian.PutUint32(pe[sec1+12:], 0x3000)
	binary.LittleEndian.PutUint32(pe[sec1+16:], 0x200)
	binary.LittleEndian.PutUint32(pe[sec1+20:], 0x600)

	for i := 0x400; i < 0x600; i++ {
		pe[i] = 0x11
	}
	for i := 0x600; i < 0x800; i++ {
		pe[i] = 0xCC
	}

	base, sz, err := manualMap(pe)
	if err != nil {
		t.Fatalf("manualMap: %v", err)
	}
	defer k32Free(base, sz)

	mem := unsafe.Slice((*byte)(unsafe.Pointer(base)), sz)
	for i := 0x2000; i < 0x2200; i++ {
		if mem[i] != 0x11 {
			t.Fatalf(".data 初始化区被破坏 @0x%x: got=0x%02x want=0x11", i, mem[i])
		}
	}
	for i := 0x2200; i < 0x2400; i++ {
		if mem[i] != 0x00 {
			t.Fatalf(".bss 零填充区被相邻节数据污染 @0x%x: got=0x%02x want=0x00", i, mem[i])
		}
	}
}
