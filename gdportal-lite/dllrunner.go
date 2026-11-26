//go:build windows && 386

package main

// dllRunner: legacy windows/386 原生算法执行引擎 (VirtualAlloc RWX + VEH + 子进程 worker)
// 默认全平台已切换为纯 Go x86emu；设置环境变量 DLL_ENGINE=native 可切回本引擎。

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// 编译期强制 32 位校验: GOARCH=amd64 等非 32 位平台直接编译报错。
const (
	_mustBuildWithGOARCH386Min uintptr = 4 - unsafe.Sizeof(uintptr(0))
	_mustBuildWithGOARCH386Max uintptr = unsafe.Sizeof(uintptr(0)) - 4
)

const (
	dllPoolRVA   = 0xB088 // 密钥池 RVA
	dllCfgL2RVA  = 0xB181 // l2 (IV/K2 长度)
	dllCfgL1RVA  = 0xB183 // l1 (KEY1 长度)
	dllCfgOffRVA = 0xB186 // KEY1 池内偏移
	dllTextVA    = 0x1000
	dllTextROFF  = 0x400
	dllCtxRVA    = 0xB5B0 // AutoZSM 上下文对象指针槽
)

const dllWorkerMaxCalls = 200

func preferNativeDLLEngine() bool {
	return os.Getenv("DLL_ENGINE") == "native"
}

func newNativeDLLCipher(pe []byte, keyhex string) (Cipher, error) {
	return &dllCipher{pe: pe, keyhex: keyhex}, nil
}

// ---- Win32 API 预解析缓存 (避免在 VEH / 回调内分配堆内存或加锁) ----

var (
	win32Once sync.Once
	modk32    = syscall.NewLazyDLL("kernel32.dll")

	procVirtualAlloc       *syscall.LazyProc
	procVirtualFree        *syscall.LazyProc
	procVirtualQuery       *syscall.LazyProc
	procLoadLibA           *syscall.LazyProc
	procLoadLibW           *syscall.LazyProc
	procGetModHandleA      *syscall.LazyProc
	procGetModHandleW      *syscall.LazyProc
	procGetProcAddress     *syscall.LazyProc
	procCreateThread       *syscall.LazyProc
	procWaitForSingleObj   *syscall.LazyProc
	procGetExitCodeThread  *syscall.LazyProc
	procCloseHandle        *syscall.LazyProc
	procSuspendThread      *syscall.LazyProc
	procResumeThread       *syscall.LazyProc
	procGetThreadContext   *syscall.LazyProc
	procGetCurrentThreadId *syscall.LazyProc
	procExitThread         *syscall.LazyProc
	procAddVEH             *syscall.LazyProc
	procRemoveVEH          *syscall.LazyProc

	addrVirtualAlloc       uintptr
	addrVirtualQuery       uintptr
	addrGetCurrentThreadId uintptr
	addrExitThread         uintptr
	addrGetProcAddress     uintptr
	addrLoadLibraryA       uintptr
	addrLoadLibraryW       uintptr
	addrGetModuleHandleA   uintptr
	addrGetModuleHandleW   uintptr
	addrCreateThread       uintptr
)

func initWin32Procs() {
	win32Once.Do(func() {
		procVirtualAlloc = modk32.NewProc("VirtualAlloc")
		procVirtualFree = modk32.NewProc("VirtualFree")
		procVirtualQuery = modk32.NewProc("VirtualQuery")
		procLoadLibA = modk32.NewProc("LoadLibraryA")
		procLoadLibW = modk32.NewProc("LoadLibraryW")
		procGetModHandleA = modk32.NewProc("GetModuleHandleA")
		procGetModHandleW = modk32.NewProc("GetModuleHandleW")
		procGetProcAddress = modk32.NewProc("GetProcAddress")
		procCreateThread = modk32.NewProc("CreateThread")
		procWaitForSingleObj = modk32.NewProc("WaitForSingleObject")
		procGetExitCodeThread = modk32.NewProc("GetExitCodeThread")
		procCloseHandle = modk32.NewProc("CloseHandle")
		procSuspendThread = modk32.NewProc("SuspendThread")
		procResumeThread = modk32.NewProc("ResumeThread")
		procGetThreadContext = modk32.NewProc("GetThreadContext")
		procGetCurrentThreadId = modk32.NewProc("GetCurrentThreadId")
		procExitThread = modk32.NewProc("ExitThread")
		procAddVEH = modk32.NewProc("AddVectoredExceptionHandler")
		procRemoveVEH = modk32.NewProc("RemoveVectoredExceptionHandler")

		addrVirtualAlloc = procVirtualAlloc.Addr()
		addrVirtualQuery = procVirtualQuery.Addr()
		addrGetCurrentThreadId = procGetCurrentThreadId.Addr()
		addrExitThread = procExitThread.Addr()
		addrGetProcAddress = procGetProcAddress.Addr()
		addrLoadLibraryA = procLoadLibA.Addr()
		addrLoadLibraryW = procLoadLibW.Addr()
		addrGetModuleHandleA = procGetModHandleA.Addr()
		addrGetModuleHandleW = procGetModHandleW.Addr()
		addrCreateThread = procCreateThread.Addr()
	})
}

// peTextInfo 从 PE 头提取 ImageBase、.text 节位置/大小及 SizeOfImage。
func peTextInfo(img []byte) (imageBase, textVA, textROFF, textSize, sizeImage uint32) {
	imageBase = 0x10000000
	textVA = dllTextVA
	textROFF = dllTextROFF
	textSize = 0x8000
	sizeImage = 0x10000
	if len(img) < 0x100 || img[0] != 'M' || img[1] != 'Z' {
		return
	}
	e := int(le32(img, 0x3C))
	if e < 0 || e+24+60 > len(img) || !bytesEq2(img[e:], "PE\x00\x00") {
		return
	}
	imageBase = le32(img, e+24+28)
	sizeImage = le32(img, e+24+56)
	nsec := int(le16(img, e+6))
	secOff := e + 24 + int(le16(img, e+20))
	for k := 0; k < nsec && secOff+40*(k+1) <= len(img); k++ {
		s := img[secOff+40*k : secOff+40*(k+1)]
		name := strings.TrimRight(string(s[:8]), "\x00")
		if name == ".text" || k == 0 {
			va := le32(s, 12)
			vsz := le32(s, 8)
			roff := le32(s, 20)
			rsz := le32(s, 24)
			if va != 0 {
				textVA = va
			}
			if roff != 0 {
				textROFF = roff
			}
			sz := maxU32(vsz, rsz)
			if sz != 0 {
				textSize = sz
			}
			if name == ".text" {
				break
			}
		}
	}
	return
}

// manualMap 手工映射算法 DLL 到内存 (不调 DllMain, 避免内置探测线程阻塞;
// 节数据按 VA 复制并截断到镜像/文件边界，保留 .data 未初始化尾部给运行态)。
func manualMap(img []byte) (uintptr, uint32, error) {
	initWin32Procs()
	if len(img) < 0x400 || img[0] != 'M' || img[1] != 'Z' {
		return 0, 0, errors.New("非 PE 镜像")
	}
	e := int(le32(img, 0x3C))
	if e < 0 || e+24+96+44 > len(img) || !bytesEq2(img[e:], "PE\x00\x00") {
		return 0, 0, errors.New("非 PE 镜像")
	}
	imageBase := le32(img, e+24+28)
	sizeImage := le32(img, e+24+56)
	nsec := int(le16(img, e+6))
	secOff := e + 24 + int(le16(img, e+20))
	if sizeImage < 0x1000 || sizeImage > 64<<20 || secOff < 0 || secOff+40*nsec > len(img) {
		return 0, 0, errors.New("PE 尺寸或节表越界")
	}
	impRVA := le32(img, e+24+96+8)  // import 目录
	relRVA := le32(img, e+24+96+40) // basereloc 目录

	base, _, _ := procVirtualAlloc.Call(uintptr(imageBase), uintptr(sizeImage), 0x3000, 0x40)
	if base != 0 {
		dllLogf("[dll] 首选基址 0x%x 分配成功 (无重定位)\n", base)
	} else {
		dllLogf("[dll] 首选基址被占, 回退随机基址 (需重定位)\n")
		base, _, _ = procVirtualAlloc.Call(0, uintptr(sizeImage), 0x3000, 0x40)
	}
	if base == 0 {
		return 0, 0, errors.New("VirtualAlloc 失败")
	}
	mem := unsafe.Slice((*byte)(unsafe.Pointer(base)), sizeImage)
	hdrCopy := minU32(uint32(len(img)), sizeImage)
	if sizeOfHeaders := le32(img, e+24+60); sizeOfHeaders > 0 && sizeOfHeaders < hdrCopy {
		hdrCopy = sizeOfHeaders
	}
	copy(mem[:hdrCopy], img[:hdrCopy])
	for k := 0; k < nsec; k++ {
		s := img[secOff+40*k : secOff+40*(k+1)]
		va, vsz, roff := le32(s, 12), le32(s, 8), le32(s, 20)
		rsz := le32(s, 16)
		if roff == 0 || roff >= uint32(len(img)) || va >= sizeImage {
			continue
		}
		// 标准 PE 语义: 只复制初始化数据 SizeOfRawData (若为 0 则回退 VirtualSize);
		// [va+rsz .. va+vsz) 为 .bss 零填充区, 绝不能把紧邻的 .reloc 节字节抄进去!
		cpLen := rsz
		if cpLen == 0 {
			cpLen = vsz
		} else if vsz > 0 && vsz < cpLen {
			cpLen = vsz
		}
		cpLen = minU32(cpLen, uint32(len(img))-roff)
		cpLen = minU32(cpLen, sizeImage-va)
		if cpLen > 0 {
			copy(mem[va:va+cpLen], img[roff:roff+cpLen])
		}
	}
	// 重定位
	delta := uint32(base) - imageBase
	relCount := 0
	if delta != 0 && relRVA != 0 && relRVA < sizeImage {
		off := relRVA
		for off+8 <= sizeImage {
			pageRVA, bsz := le32(mem, int(off)), le32(mem, int(off+4))
			if bsz < 8 || bsz > 0x100000 || off+bsz > sizeImage {
				break
			}
			for j := off + 8; j+2 <= off+bsz; j += 2 {
				w := le16(mem, int(j))
				typ, o := w>>12, w&0xFFF
				if typ == 3 { // HIGHLOW
					p := pageRVA + uint32(o)
					if p+4 <= sizeImage {
						v := le32(mem, int(p))
						binary.LittleEndian.PutUint32(mem[p:p+4], v+delta)
						relCount++
					}
				}
			}
			off += bsz
		}
	}
	// 导入表
	dllHandles := map[string]uintptr{}
	loadDLL := func(name string) (uintptr, error) {
		key := strings.ToLower(name)
		if h, ok := dllHandles[key]; ok {
			return h, nil
		}
		wname, _ := syscall.UTF16PtrFromString(name)
		h, _, callErr := procLoadLibW.Call(uintptr(unsafe.Pointer(wname)))
		dllHandles[key] = h
		return h, callErr
	}
	if impRVA != 0 && impRVA < sizeImage {
		for d := impRVA; d+20 <= sizeImage; d += 20 {
			ilt, _, _, nameRva, iat := le32(mem, int(d)), le32(mem, int(d+4)), le32(mem, int(d+8)), le32(mem, int(d+12)), le32(mem, int(d+16))
			if ilt == 0 && nameRva == 0 && iat == 0 {
				break
			}
			if nameRva >= sizeImage || iat >= sizeImage {
				break
			}
			dllName := cstrInMem(mem, nameRva, sizeImage)
			hmod, callErr := loadDLL(dllName)
			if hmod == 0 {
				fmt.Fprintf(os.Stderr, "[dll] ★导入库加载失败: %q nameRva=0x%x err=%v\n", dllName, nameRva, callErr)
				continue
			}
			t := iat
			if ilt != 0 {
				t = ilt
			}
			for j := 0; ; j++ {
				tSlot := t + uint32(4*j)
				iSlot := iat + uint32(4*j)
				if tSlot+4 > sizeImage || iSlot+4 > sizeImage {
					break
				}
				thunk := le32(mem, int(tSlot))
				if thunk == 0 {
					break
				}
				var proc uintptr
				if thunk&0x80000000 != 0 {
					proc, _, _ = syscall.SyscallN(addrGetProcAddress, hmod, uintptr(thunk&0xFFFF))
				} else {
					if thunk+2 >= sizeImage {
						break
					}
					// 快路径: 直接把内存里 NUL 结尾的 ASCII 导入名指针喂给 GetProcAddress，零 Go 字符串分配
					proc, _, _ = syscall.SyscallN(addrGetProcAddress, hmod, base+uintptr(thunk+2))
					if proc == 0 {
						fname := cstrInMem(mem, thunk+2, sizeImage)
						for _, fb := range []string{"VCRUNTIME140.dll", "ucrtbase.dll", "ntdll.dll", "api-ms-win-crt-runtime-l1-1-0.dll"} {
							hfb, _ := loadDLL(fb)
							if hfb == 0 {
								continue
							}
							proc, _, _ = syscall.SyscallN(addrGetProcAddress, hfb, base+uintptr(thunk+2))
							if proc != 0 {
								dllLogf("[dll]   %s!%s → fallback %s 成功\n", dllName, fname, fb)
								break
							}
						}
						if proc == 0 {
							fmt.Fprintf(os.Stderr, "[dll] ★GPA失败 %s!%q hmod=0x%x\n", dllName, fname, hmod)
						}
					}
				}
				if proc != 0 {
					binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(proc))
				} else {
					fmt.Fprintf(os.Stderr, "[dll] ★导入函数解析失败: %s#%s\n", dllName, funcName(mem, thunk))
				}
			}
		}
	}
	dllLogf("[dll] 重定位补丁 %d 处\n", relCount)
	return base, sizeImage, nil
}

func cstrInMem(mem []byte, off, limit uint32) string {
	if off >= limit || off >= uint32(len(mem)) {
		return ""
	}
	max := limit
	if uint32(len(mem)) < max {
		max = uint32(len(mem))
	}
	end := off
	for end < max && mem[end] != 0 {
		end++
	}
	return string(mem[off:end])
}

// detectCtxRVA 自动探测模板的宿主上下文对象指针槽:
// Code 主体前 0x180 字节内, 唯一被高频引用 (≥4 次) 的 .rdata/.data 绝对地址。
func detectCtxRVA(img []byte, codeRVA uint32) uint32 {
	imageBase, textVA, textROFF, _, sizeImage := peTextInfo(img)
	start := int(textROFF) + int(codeRVA) - int(textVA)
	if start < 0 || start >= len(img) {
		return 0
	}
	end := start + 0x180
	if end > len(img)-4 {
		end = len(img) - 4
	}
	loAddr := imageBase + 0x1000
	hiAddr := imageBase + sizeImage
	cnt := map[uint32]int{}
	for i := start; i+4 <= end; i++ {
		v := le32(img, i)
		if v >= loAddr && v < hiAddr {
			cnt[v-imageBase]++
		}
	}
	best, bestC := uint32(0), 0
	for r, c := range cnt {
		if c > bestC || (c == bestC && r > best) {
			best, bestC = r, c
		}
	}
	return best
}

// findSelfInitVtable 从 Code 自初始化代码提取 ctx 对象 vtable RVA:
// 模式 `mov dword ptr [esi/edi], imm32` (C7 06/C7 07), imm 在镜像地址范围。
func findSelfInitVtable(img []byte, codeRVA uint32) uint32 {
	imageBase, textVA, textROFF, _, sizeImage := peTextInfo(img)
	start := int(textROFF) + int(codeRVA) - int(textVA)
	if start < 0 || start >= len(img) {
		return 0xA000
	}
	end := start + 0x140
	loAddr := imageBase + 0x1000
	hiAddr := imageBase + sizeImage
	for i := start; i+6 <= end && i+6 <= len(img); i++ {
		if img[i] == 0xC7 && (img[i+1] == 0x06 || img[i+1] == 0x07) {
			v := le32(img, i+2)
			if v >= loAddr && v < hiAddr {
				return v - imageBase
			}
		}
	}
	return 0xA000 // 兜底: gen 家族默认
}

// initRuntimeState 复刻官方加载期对 .data 运行态结构区的初始化
func initRuntimeState(mem []byte, base uintptr, ctxRVA, vtblRVA uint32) ([]uintptr, error) {
	initWin32Procs()
	if ctxRVA < 0x10 || int(ctxRVA)+0xC8 > len(mem) {
		return nil, fmt.Errorf("ctxRVA 越界: 0x%x", ctxRVA)
	}
	desc := uint32(0)
	if vtblRVA > 8 {
		desc = vtblRVA - 8
	}
	lo, hi := int(ctxRVA)-0x10, int(ctxRVA)+0xC8
	for i := lo; i < hi; i++ {
		mem[i] = 0
	}
	put := func(rva uint32, v uint32) {
		if int(rva)+4 <= len(mem) {
			binary.LittleEndian.PutUint32(mem[rva:rva+4], v)
		}
	}
	var allocs []uintptr
	allocBuf := func() uint32 {
		p, _, _ := procVirtualAlloc.Call(0, 0x100, 0x3000, 0x04) // PAGE_READWRITE
		if p != 0 {
			allocs = append(allocs, p)
		}
		return uint32(p)
	}
	put(ctxRVA-8, 1)
	put(ctxRVA-4, 0)
	put(ctxRVA+4, uint32(base)+desc)
	put(ctxRVA+8, 1)
	put(ctxRVA+0xC, 0x20)
	put(ctxRVA+0x10, allocBuf())
	put(ctxRVA+0x14, uint32(base)+desc)
	put(ctxRVA+0x18, 1)
	put(ctxRVA+0x1C, 0x20)
	put(ctxRVA+0x20, allocBuf())
	put(ctxRVA+0x24, 0xFFFFFFFF)
	put(ctxRVA+0x28, 0xFFFFFFFF)
	put(ctxRVA+0x2C, 0xFFFFFFFF)
	return allocs, nil
}

// ---- gen/AES 通用 InnerDSAssist 替身 ----
var (
	innerOnce             sync.Once
	innerAllocBuf         uintptr
	innerGPAAddr          uintptr
	innerHexAddr          uintptr
	innerDupAddr          uintptr
	innerStub1Addr        uintptr
	innerFakeObj          uintptr
	innerFactoryAddr      uintptr
	innerHexDecAddr       uintptr
	innerLoadLibAAddr     uintptr
	innerLoadLibWAddr     uintptr
	innerGetModAAddr      uintptr
	innerGetModWAddr      uintptr
	innerCreateThreadAddr uintptr
)

func initInnerCallbacks() {
	initWin32Procs()
	innerOnce.Do(func() {
		innerAllocBuf = syscall.NewCallback(allocStateBuf)
		innerGPAAddr = syscall.NewCallback(innerGPAHook)
		innerHexAddr = syscall.NewCallback(hexEncodeBuf)
		innerHexDecAddr = syscall.NewCallback(hexDecodeBuf)
		innerDupAddr = syscall.NewCallback(cstrDup)
		innerStub1Addr = syscall.NewCallback(func(a uintptr) uintptr { return 0 })
		innerFakeObj = makeFakeObject(8)
		innerFactoryAddr = syscall.NewCallback(func(a, b uintptr) uintptr { return innerFakeObj })
		innerLoadLibAAddr = syscall.NewCallback(loadLibAHook)
		innerLoadLibWAddr = syscall.NewCallback(loadLibWHook)
		innerGetModAAddr = syscall.NewCallback(getModAHook)
		innerGetModWAddr = syscall.NewCallback(getModWHook)
		innerCreateThreadAddr = syscall.NewCallback(func(a1, a2, a3, a4, a5, a6 uintptr) uintptr { return 0 })
	})
}

func makeFakeObject(nMethods int) uintptr {
	tbl, _, _ := procVirtualAlloc.Call(0, 0x100, 0x3000, 0x04) // PAGE_READWRITE
	if tbl == 0 {
		return 0
	}
	obj, _, _ := procVirtualAlloc.Call(0, 0x400, 0x3000, 0x04) // PAGE_READWRITE
	if obj == 0 {
		k32Free(tbl, 0)
		return 0
	}
	tv := unsafe.Slice((*byte)(unsafe.Pointer(tbl)), 0x100)
	for i := 0; i < nMethods && i < 32; i++ {
		binary.LittleEndian.PutUint32(tv[4*i:4*i+4], uint32(innerStub1Addr))
	}
	ov := unsafe.Slice((*byte)(unsafe.Pointer(obj)), 0x400)
	binary.LittleEndian.PutUint32(ov[0:4], uint32(tbl))
	return obj
}

// allocStateBuf 复刻 Svr 0x23e30: stdcall(len) → 16B 头{+4=len, +8=dataptr} + 数据区
func allocStateBuf(ln uintptr) uintptr {
	initWin32Procs()
	blk, _, _ := syscall.SyscallN(addrVirtualAlloc, 0, 64+ln, 0x3000, 0x04)
	if blk == 0 {
		return 0
	}
	mem := unsafe.Slice((*byte)(unsafe.Pointer(blk)), 64+ln)
	binary.LittleEndian.PutUint32(mem[4:8], uint32(ln))
	binary.LittleEndian.PutUint32(mem[8:12], uint32(blk+16))
	return blk
}

// hexEncodeBuf 复刻 Svr 0x23d40→0x266e0 (ord9)
func hexEncodeBuf(dp, ln uintptr) uintptr {
	initWin32Procs()
	if dp == 0 || ln == 0 || ln > 1<<20 {
		return 0
	}
	blk, _, _ := syscall.SyscallN(addrVirtualAlloc, 0, 2*ln+16, 0x3000, 0x04)
	if blk == 0 {
		return 0
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(dp)), ln)
	out := unsafe.Slice((*byte)(unsafe.Pointer(blk)), 2*ln+1)
	const hexd = "0123456789ABCDEF"
	for i := uint32(0); i < uint32(ln); i++ {
		b := src[i]
		out[2*i] = hexd[b>>4]
		out[2*i+1] = hexd[b&0xF]
	}
	out[2*ln] = 0
	return blk
}

// hexDecodeBuf 复刻 Svr ord5 (0x23e70): stdcall(hexStr) → statebuf。
func hexDecodeBuf(strPtr uintptr) uintptr {
	initWin32Procs()
	if strPtr == 0 {
		return 0
	}
	s := strings.TrimSpace(goCStr(strPtr))
	data, err := hex.DecodeString(s)
	if err != nil || len(data) == 0 {
		fmt.Fprintf(os.Stderr, "[dll] hexDecodeBuf 解码失败: err=%v len=%d\n", err, len(s))
		return 0
	}
	n := len(data)
	blk, _, _ := syscall.SyscallN(addrVirtualAlloc, 0, uintptr(64+n+1), 0x3000, 0x04)
	if blk == 0 {
		return 0
	}
	mem := unsafe.Slice((*byte)(unsafe.Pointer(blk)), 64+n+1)
	binary.LittleEndian.PutUint32(mem[4:8], uint32(n))
	binary.LittleEndian.PutUint32(mem[8:12], uint32(blk+16))
	copy(mem[16:], data)
	mem[16+n] = 0
	return blk
}

func goCStr(p uintptr) string {
	if p == 0 {
		return ""
	}
	var b []byte
	for i := uintptr(0); i < 1<<20; i++ {
		c := *(*byte)(unsafe.Pointer(p + i))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

func cstrDup(p uintptr) uintptr {
	initWin32Procs()
	if p == 0 {
		return 0
	}
	n := 0
	for n < 65536 {
		if *(*byte)(unsafe.Pointer(p + uintptr(n))) == 0 {
			break
		}
		n++
	}
	blk, _, _ := syscall.SyscallN(addrVirtualAlloc, 0, uintptr(n+16), 0x3000, 0x04)
	if blk == 0 {
		return 0
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(blk)), n+1)
	src := unsafe.Slice((*byte)(unsafe.Pointer(p)), n)
	copy(dst, src)
	dst[n] = 0
	return blk
}

func innerGPAHook(hmod, name uintptr) uintptr {
	if hmod != 1 {
		addr, _, _ := syscall.SyscallN(addrGetProcAddress, hmod, name)
		return addr
	}
	switch name {
	case 9:
		return innerHexAddr
	case 10:
		return innerDupAddr
	case 5:
		return innerHexDecAddr
	case 4:
		return innerAllocBuf
	}
	if name >= 0x10000 {
		return innerFactoryAddr
	}
	dllLogf("[dll] 未知 InnerDSAssist ord%d → 0\n", name)
	return 0
}

func loadLibAHook(name uintptr) uintptr {
	if name != 0 && strings.Contains(strings.ToLower(goAscii(name)), "innerdsassist") {
		return 1
	}
	addr, _, _ := syscall.SyscallN(addrLoadLibraryA, name)
	return addr
}

func loadLibWHook(name uintptr) uintptr {
	if name != 0 && strings.Contains(strings.ToLower(goWideAscii(name)), "innerdsassist") {
		return 1
	}
	addr, _, _ := syscall.SyscallN(addrLoadLibraryW, name)
	return addr
}

func getModAHook(name uintptr) uintptr {
	if name != 0 && strings.Contains(strings.ToLower(goAscii(name)), "innerdsassist") {
		return 1
	}
	addr, _, _ := syscall.SyscallN(addrGetModuleHandleA, name)
	return addr
}

func getModWHook(name uintptr) uintptr {
	if name != 0 && strings.Contains(strings.ToLower(goWideAscii(name)), "innerdsassist") {
		return 1
	}
	addr, _, _ := syscall.SyscallN(addrGetModuleHandleW, name)
	return addr
}

func goAscii(p uintptr) string {
	if p == 0 {
		return ""
	}
	b := make([]byte, 0, 64)
	for i := 0; i < 260; i++ {
		c := *(*byte)(unsafe.Pointer(p + uintptr(i)))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

func goWideAscii(p uintptr) string {
	if p == 0 {
		return ""
	}
	b := make([]byte, 0, 64)
	for i := 0; i < 260; i++ {
		w := *(*uint16)(unsafe.Pointer(p + uintptr(2*i)))
		if w == 0 {
			break
		}
		if w < 128 {
			b = append(b, byte(w))
		}
	}
	return string(b)
}

// patchIATHooks 遍历映射镜像导入目录 (+ 地址兜底匹配), 精确替换 CreateThread / GPA / LoadLibrary* / GetModuleHandle*。
func patchIATHooks(mem []byte) (int, int) {
	initWin32Procs()
	initInnerCallbacks()
	if len(mem) < 0x400 {
		return 0, 0
	}
	e := int(le32(mem, 0x3C))
	if e < 0 || e+24+96+16 > len(mem) || !bytesEq2(mem[e:], "PE\x00\x00") {
		return 0, 0
	}
	impRVA := le32(mem, e+24+96+8)
	sizeImage := uint32(len(mem))
	nHooks, nCT := 0, 0

	patchByName := func(dllName, fnName string, iSlot uint32) bool {
		lowDLL := strings.ToLower(dllName)
		if !strings.EqualFold(dllName, "kernel32.dll") && !strings.HasPrefix(lowDLL, "api-ms-win-core-") {
			return false
		}
		switch fnName {
		case "CreateThread":
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerCreateThreadAddr))
			nCT++
			return true
		case "GetProcAddress":
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerGPAAddr))
			dllLogf("[dll]   IAT 槽 @RVA 0x%x (GetProcAddress) → GPA 替身\n", iSlot)
			nHooks++
			return true
		case "LoadLibraryA":
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerLoadLibAAddr))
			dllLogf("[dll]   IAT 槽 @RVA 0x%x (LoadLibraryA) → InnerDSAssist 替身\n", iSlot)
			nHooks++
			return true
		case "LoadLibraryW":
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerLoadLibWAddr))
			dllLogf("[dll]   IAT 槽 @RVA 0x%x (LoadLibraryW) → InnerDSAssist 替身\n", iSlot)
			nHooks++
			return true
		case "GetModuleHandleA":
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerGetModAAddr))
			nHooks++
			return true
		case "GetModuleHandleW":
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerGetModWAddr))
			nHooks++
			return true
		}
		return false
	}

	patchByAddr := func(iSlot uint32) {
		v := le32(mem, int(iSlot))
		switch v {
		case uint32(addrCreateThread):
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerCreateThreadAddr))
			nCT++
		case uint32(addrGetProcAddress):
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerGPAAddr))
			dllLogf("[dll]   IAT 槽 @RVA 0x%x (GetProcAddress) → GPA 替身\n", iSlot)
			nHooks++
		case uint32(addrLoadLibraryA):
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerLoadLibAAddr))
			dllLogf("[dll]   IAT 槽 @RVA 0x%x (LoadLibraryA) → InnerDSAssist 替身\n", iSlot)
			nHooks++
		case uint32(addrLoadLibraryW):
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerLoadLibWAddr))
			nHooks++
		case uint32(addrGetModuleHandleA):
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerGetModAAddr))
			nHooks++
		case uint32(addrGetModuleHandleW):
			binary.LittleEndian.PutUint32(mem[iSlot:iSlot+4], uint32(innerGetModWAddr))
			nHooks++
		}
	}

	if impRVA != 0 && impRVA < sizeImage {
		for d := impRVA; d+20 <= sizeImage; d += 20 {
			ilt, _, _, nameRva, iat := le32(mem, int(d)), le32(mem, int(d+4)), le32(mem, int(d+8)), le32(mem, int(d+12)), le32(mem, int(d+16))
			if ilt == 0 && nameRva == 0 && iat == 0 {
				break
			}
			if iat >= sizeImage {
				break
			}
			dllName := cstrInMem(mem, nameRva, sizeImage)
			for j := 0; ; j++ {
				iSlot := iat + uint32(4*j)
				if iSlot+4 > sizeImage {
					break
				}
				if le32(mem, int(iSlot)) == 0 {
					break
				}
				done := false
				if ilt != 0 && ilt+uint32(4*j)+4 <= sizeImage {
					thunk := le32(mem, int(ilt+uint32(4*j)))
					if thunk == 0 {
						break
					}
					if thunk&0x80000000 == 0 && thunk+2 < sizeImage {
						fnName := cstrInMem(mem, thunk+2, sizeImage)
						done = patchByName(dllName, fnName, iSlot)
					}
				}
				if !done {
					patchByAddr(iSlot)
				}
			}
		}
	}
	return nHooks, nCT
}

// ---- DLL 常驻会话 (单次映射 + DllMain，多次调用 Code/DeCode) ----

type dllSession struct {
	base       uintptr
	szImg      uint32
	mem        []byte
	ctxPage    uintptr
	stateBufs  []uintptr
	codeRVA    uint32
	decRVA     uint32
	timedOut   bool
}

func newDllSession(img []byte, keyhex string) (*dllSession, error) {
	initWin32Procs()
	codeRVA, err := findFuncRVA(img, dllCodePat)
	if err != nil {
		return nil, fmt.Errorf("Code: %v", err)
	}
	decRVA, err := findFuncRVA(img, dllDecPat)
	if err != nil {
		return nil, fmt.Errorf("DeCode: %v", err)
	}
	kh, err := hex.DecodeString(keyhex)
	if err != nil || len(kh) < 16 {
		return nil, errors.New("keyhex 非法")
	}
	dllLogf("[dll] 手工映射中...\n")
	base, szImg, err := manualMap(img)
	if err != nil {
		return nil, err
	}
	dllLogf("[dll] 已映射 base=0x%x size=0x%x\n", base, szImg)
	s := &dllSession{
		base:    base,
		szImg:   szImg,
		mem:     unsafe.Slice((*byte)(unsafe.Pointer(base)), szImg),
		codeRVA: codeRVA,
		decRVA:  decRVA,
	}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	atomic.StoreUint32(&imgBase, uint32(base))
	atomic.StoreUint32(&imgSize, szImg)

	nHooks, nCT := patchIATHooks(s.mem)
	if nCT > 0 {
		dllLogf("[dll] CreateThread IAT 槽已接管 ×%d\n", nCT)
	}
	if nHooks > 0 {
		dllLogf("[dll] IAT 替身槽已替换 ×%d\n", nHooks)
	} else {
		dllLogf("[dll] (警告) 未定位到 GPA/LL 槽\n")
	}

	// AES 模板才有静态密钥池/窗口配置
	if bytes.Contains(img, aesSboxSig) {
		if dllCfgOffRVA >= szImg || dllCfgL1RVA >= szImg {
			return nil, fmt.Errorf("cfg RVA 越界")
		}
		l1 := s.mem[dllCfgL1RVA]
		off1 := s.mem[dllCfgOffRVA]
		if l1 == 0 {
			return nil, fmt.Errorf("cfg 非法 l1=%d off1=%d", l1, off1)
		}
		slot := dllPoolRVA + uint32(off1) + uint32(l1)
		if slot+16 > szImg {
			return nil, fmt.Errorf("K2 槽越界: 0x%x", slot)
		}
		copy(s.mem[slot:slot+16], kh[:16])
		dllLogf("[dll] AES 模板: K2 槽 @0x%x 已补丁\n", slot)
	} else {
		dllLogf("[dll] gen 模板: 无静态池, 跳过 K2 补丁\n")
	}

	ctxRVA := detectCtxRVA(img, codeRVA)
	if ctxRVA == 0 {
		ctxRVA = dllCtxRVA
	}
	pg, _, _ := procVirtualAlloc.Call(0, 0x1000, 0x3000, 0x40) // 含 0xC3 ret 存根
	if pg == 0 {
		return nil, errors.New("上下文页分配失败")
	}
	s.ctxPage = pg
	ctxMem := unsafe.Slice((*byte)(unsafe.Pointer(pg)), 0x1000)
	fakeObj := pg + 0x40
	binary.LittleEndian.PutUint32(ctxMem[0x40:0x44], uint32(pg+0x80))
	binary.LittleEndian.PutUint32(ctxMem[0x44:0x48], 1)
	ctxMem[0x80] = 0xC3
	vtblRVA := findSelfInitVtable(img, codeRVA)
	bufs, rerr := initRuntimeState(s.mem, base, ctxRVA, vtblRVA)
	if rerr != nil {
		return nil, rerr
	}
	s.stateBufs = bufs
	if int(ctxRVA)+4 <= len(s.mem) {
		binary.LittleEndian.PutUint32(s.mem[ctxRVA:ctxRVA+4], uint32(fakeObj))
	}
	dllLogf("[dll] 上下文对象 @0x%x → 槽 0x%x 已写入 (vtbl RVA 0x%x, 运行态区已重建)\n", fakeObj, ctxRVA, vtblRVA)

	_, textVA, _, textSize, _ := peTextInfo(img)
	textEnd := textVA + textSize
	n1 := patchAntiTamperCallSite(s.mem, codeRVA, textVA, textEnd)
	n2 := patchAntiTamperCallSite(s.mem, decRVA, textVA, textEnd)
	dllLogf("[dll] 反篡改调用点: Code 命中 %d, DeCode 命中 %d\n", n1, n2)

	if os.Getenv("DLL_INIT") != "0" {
		e := int(le32(img, 0x3C))
		ep := le32(img, e+24+16)
		if ep != 0 && ep < szImg {
			ret, err := callOnThreadTO(base+uintptr(ep), 15000, uintptr(base), 1, 1)
			dllLogf("[dll] DllMain(base,ATTACH,1) → ret=0x%x err=%v\n", ret, err)
			if err != nil {
				if errors.Is(err, errCallTimeout) {
					s.timedOut = true
				}
				dllLogf("[dll] (警告) DllMain 未正常返回, 继续 Code 调用\n")
			}
		}
	}
	ok = true
	return s, nil
}

func (s *dllSession) Call(mode string, input []byte) (string, bool, error) {
	initWin32Procs()
	fnRVA := s.codeRVA
	if mode == "dec" {
		fnRVA = s.decRVA
	}
	// 输入缓冲放进不可移动的非托管堆页 (PAGE_READWRITE), 彻底隔离 Go GC
	inPtr, _, _ := procVirtualAlloc.Call(0, uintptr(len(input)+16), 0x3000, 0x04)
	if inPtr == 0 {
		return "", false, errors.New("输入缓冲分配失败")
	}
	inBuf := unsafe.Slice((*byte)(unsafe.Pointer(inPtr)), len(input)+1)
	copy(inBuf, input)
	inBuf[len(input)] = 0

	atomic.StoreUint32(&imgBase, uint32(s.base))
	atomic.StoreUint32(&imgSize, s.szImg)

	dllLogf("[dll] 调用 Code/DeCode @0x%x mode=%s (原生线程桩)...\n", s.base+uintptr(fnRVA), mode)
	ret, err := callOnThread(s.base+uintptr(fnRVA), inPtr)
	if err != nil {
		to := errors.Is(err, errCallTimeout)
		if to {
			s.timedOut = true
		} else {
			k32Free(inPtr, 0)
		}
		return "", to, err
	}
	k32Free(inPtr, 0)
	dllLogf("[dll] 返回 0x%x\n", ret)
	if ret == 0 {
		return "", false, errors.New("算法函数返回空")
	}
	var out []byte
	for i := 0; i < 1<<20; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(ret) + uintptr(i)))
		if b == 0 {
			break
		}
		out = append(out, b)
	}
	return string(out), false, nil
}

func (s *dllSession) Close() {
	if s.timedOut {
		// 超时后仍有原生线程运行在映射区，不可释放以免 UAF
		return
	}
	for _, b := range s.stateBufs {
		k32Free(b, 0)
	}
	s.stateBufs = nil
	if s.ctxPage != 0 {
		k32Free(s.ctxPage, 0)
		s.ctxPage = 0
	}
	if s.base != 0 {
		k32Free(s.base, 0)
		s.base = 0
	}
}

// ---- 二进制管道隔离 Worker (-dllworker) ----

func writeFrame(w *bufio.Writer, b []byte) error {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(b) > 0 {
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(r *bufio.Reader, maxLen uint32) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n > maxLen {
		return nil, fmt.Errorf("帧超长: %d", n)
	}
	buf := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func writeWorkerResp(w *bufio.Writer, ok bool, payload []byte) error {
	st := byte(0)
	if !ok {
		st = 1
	}
	if err := w.WriteByte(st); err != nil {
		return err
	}
	if err := writeFrame(w, payload); err != nil {
		return err
	}
	return w.Flush()
}

// runDllWorker 作为独立隔离进程运行: 从 stdin 收取 PE+keyhex 初始化会话，循环响应 enc/dec 请求。
func runDllWorker(in io.Reader, out io.Writer) error {
	br := bufio.NewReader(in)
	bw := bufio.NewWriter(out)

	pe, err := readFrame(br, 32<<20)
	if err != nil {
		_ = writeWorkerResp(bw, false, []byte("读取 PE 失败: "+err.Error()))
		return err
	}
	keyBytes, err := readFrame(br, 4096)
	if err != nil {
		_ = writeWorkerResp(bw, false, []byte("读取 keyhex 失败: "+err.Error()))
		return err
	}
	sess, err := newDllSession(pe, string(keyBytes))
	if err != nil {
		_ = writeWorkerResp(bw, false, []byte(err.Error()))
		return err
	}
	defer sess.Close()
	if err := writeWorkerResp(bw, true, nil); err != nil {
		return err
	}

	for {
		op, err := br.ReadByte()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if op == 0 {
			return nil
		}
		data, err := readFrame(br, 16<<20)
		if err != nil {
			return err
		}
		mode := "enc"
		if op == 2 {
			mode = "dec"
		}
		res, timedOut, cerr := sess.Call(mode, data)
		if cerr != nil {
			_ = writeWorkerResp(bw, false, []byte(cerr.Error()))
			if timedOut {
				os.Exit(1) // 线程已卡死，立即退出由 OS 回收全部内存
			}
			continue
		}
		if err := writeWorkerResp(bw, true, []byte(res)); err != nil {
			return err
		}
	}
}

type dllWorker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	bw     *bufio.Writer
	br     *bufio.Reader
	stderr *cappedBuffer
}

type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buf.Len() < 8192 {
		rem := 8192 - c.buf.Len()
		if len(p) > rem {
			c.buf.Write(p[:rem])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.TrimSpace(c.buf.String())
}

func startDllWorker(pe []byte, keyhex string) (*dllWorker, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{"-dllworker"}
	if isDebugMode() {
		args = append(args, "-debug")
	}
	cmd := exec.Command(self, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	errBuf := &cappedBuffer{}
	cmd.Stderr = errBuf
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, err
	}
	w := &dllWorker{
		cmd:    cmd,
		stdin:  stdin,
		bw:     bufio.NewWriter(stdin),
		br:     bufio.NewReader(stdout),
		stderr: errBuf,
	}

	type initRes struct {
		err error
	}
	ch := make(chan initRes, 1)
	go func() {
		if err := writeFrame(w.bw, pe); err != nil {
			ch <- initRes{err}
			return
		}
		if err := writeFrame(w.bw, []byte(keyhex)); err != nil {
			ch <- initRes{err}
			return
		}
		if err := w.bw.Flush(); err != nil {
			ch <- initRes{err}
			return
		}
		st, err := w.br.ReadByte()
		if err != nil {
			ch <- initRes{err}
			return
		}
		msg, err := readFrame(w.br, 64<<10)
		if err != nil {
			ch <- initRes{err}
			return
		}
		if st != 0 {
			ch <- initRes{fmt.Errorf("dllworker 初始化失败: %s", string(msg))}
			return
		}
		ch <- initRes{nil}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			w.kill()
			if s := errBuf.String(); s != "" {
				return nil, fmt.Errorf("%v (%s)", r.err, s)
			}
			return nil, r.err
		}
		return w, nil
	case <-time.After(30 * time.Second):
		w.kill()
		return nil, errors.New("dllworker 初始化超时 (30s)")
	}
}

func (w *dllWorker) call(mode string, data []byte) (string, error) {
	op := byte(1)
	if mode == "dec" {
		op = 2
	}
	type callRes struct {
		out string
		err error
	}
	ch := make(chan callRes, 1)
	go func() {
		if err := w.bw.WriteByte(op); err != nil {
			ch <- callRes{"", err}
			return
		}
		if err := writeFrame(w.bw, data); err != nil {
			ch <- callRes{"", err}
			return
		}
		if err := w.bw.Flush(); err != nil {
			ch <- callRes{"", err}
			return
		}
		st, err := w.br.ReadByte()
		if err != nil {
			ch <- callRes{"", err}
			return
		}
		payload, err := readFrame(w.br, 16<<20)
		if err != nil {
			ch <- callRes{"", err}
			return
		}
		if st != 0 {
			ch <- callRes{"", fmt.Errorf("dllalgo 退出: %s", string(payload))}
			return
		}
		ch <- callRes{strings.TrimSpace(string(payload)), nil}
	}()

	select {
	case r := <-ch:
		return r.out, r.err
	case <-time.After(25 * time.Second):
		w.kill()
		return "", errors.New("dllworker 调用超时 (25s)")
	}
}

func (w *dllWorker) close() {
	if w == nil {
		return
	}
	_ = w.bw.WriteByte(0)
	_ = w.bw.Flush()
	_ = w.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- w.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if w.cmd.Process != nil {
			_ = w.cmd.Process.Kill()
		}
		<-done
	}
}

func (w *dllWorker) kill() {
	if w == nil {
		return
	}
	_ = w.stdin.Close()
	if w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
	_ = w.cmd.Wait()
}

// dllCall 隔离进程单次调用 (不再落盘临时文件)
func dllCall(pe []byte, keyhex, mode string, input []byte) (string, error) {
	dc := &dllCipher{pe: pe, keyhex: keyhex}
	defer dc.Close()
	return dc.exec(mode, input)
}

// dllCipher 非 AES 变体加解密器: 每会话复用单个常驻隔离 worker 子进程
type dllCipher struct {
	mu     sync.Mutex
	pe     []byte
	keyhex string
	worker *dllWorker
	calls  int
}

func (c *dllCipher) exec(mode string, data []byte) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.worker != nil && c.calls >= dllWorkerMaxCalls {
		c.worker.close()
		c.worker = nil
		c.calls = 0
	}
	reused := c.worker != nil
	if c.worker == nil {
		w, err := startDllWorker(c.pe, c.keyhex)
		if err != nil {
			return "", err
		}
		c.worker = w
		c.calls = 0
	}
	out, err := c.worker.call(mode, data)
	if err != nil {
		c.worker.kill()
		c.worker = nil
		c.calls = 0
		if reused {
			w, rerr := startDllWorker(c.pe, c.keyhex)
			if rerr != nil {
				return "", err
			}
			c.worker = w
			out, err = c.worker.call(mode, data)
			if err != nil {
				c.worker.kill()
				c.worker = nil
				return "", err
			}
			c.calls++
			return out, nil
		}
		return "", err
	}
	c.calls++
	return out, nil
}

func (c *dllCipher) Encrypt(p []byte) (string, error) {
	return c.exec("enc", p)
}

func (c *dllCipher) Decrypt(h string) ([]byte, error) {
	out, err := c.exec("dec", []byte(h))
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (c *dllCipher) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.worker != nil {
		c.worker.close()
		c.worker = nil
		c.calls = 0
	}
}

// dllRun 加载镜像 DLL, 补丁 keyhex, 调用 codeFn("enc"/"dec") 处理 input, 返回字符串结果
func dllRun(img []byte, keyhex string, mode string, input []byte) (string, error) {
	sess, err := newDllSession(img, keyhex)
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, _, err := sess.Call(mode, input)
	return out, err
}

// ---- VEH 异常诊断 (定位算法 Code 崩点) ----
var lastVEH struct {
	code                                   uint32
	addr                                   uint32
	access                                 uint32
	eax, ecx, edx, ebx, esi, edi, ebp, esp uint32
	caught                                 bool
}

type exceptionRecord struct {
	Code      uint32
	Flags     uint32
	Record    uintptr
	Address   uintptr
	NumParams uint32
	Info      [15]uintptr
}

type exceptionPointers struct {
	Record  *exceptionRecord
	Context uintptr
}

var (
	vehCodeThreadID  uint32  // atomic: 受监控线程 ID; 0=未监控
	vehStubBase      uintptr // atomic: 当前 per-call 桩页基址
	vehForeignStub   uint32  // 外来线程崩溃恢复桩
	vehStackSnapshot [64]uint32
	vehStackSnapN    int
	vehFrameSnap     [20]uint32 // [ebp-0x38..ebp+0x14]
	vehFrameSnapN    int
	vehForeign       struct {
		count    int32 // atomic
		threadID uint32
		addr     uint32
		eip      uint32
		eax      uint32
		ecx      uint32
	}
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// vehCallback 严禁使用 Go 堆分配器、fmt 或 LazyProc 锁: 只调用预解析 Win32 syscall 并做原始快照。
var vehCallback = syscall.NewCallback(func(ep *exceptionPointers) uintptr {
	if ep == nil || ep.Record == nil {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}
	r := ep.Record
	if r.Code != 0xC0000005 { // ACCESS_VIOLATION
		return 0
	}
	curID, _, _ := syscall.SyscallN(addrGetCurrentThreadId)
	if uint32(curID) != atomic.LoadUint32(&vehCodeThreadID) {
		var eip uint32
		if ep.Context != 0 {
			eip = *(*uint32)(unsafe.Pointer(ep.Context + 0xB8))
		}
		baseAddr := uintptr(atomic.LoadUint32(&imgBase))
		baseSize := uintptr(atomic.LoadUint32(&imgSize))
		stubAddr := atomic.LoadUintptr(&vehStubBase)
		inDLL := baseAddr != 0 && ((r.Address >= baseAddr && r.Address < baseAddr+baseSize) ||
			(uintptr(eip) >= baseAddr && uintptr(eip) < baseAddr+baseSize))
		inStub := stubAddr != 0 && ((r.Address >= stubAddr && r.Address < stubAddr+0x1000) ||
			(uintptr(eip) >= stubAddr && uintptr(eip) < stubAddr+0x1000))
		if !inDLL && !inStub {
			// 非算法 DLL / 桩页内的异常（例如 Go runtime 或系统 DLL SEH），绝不接管
			return 0
		}
		atomic.AddInt32(&vehForeign.count, 1)
		vehForeign.threadID = uint32(curID)
		vehForeign.addr = uint32(r.Address)
		if ep.Context != 0 {
			ctx := ep.Context
			vehForeign.eax = *(*uint32)(unsafe.Pointer(ctx + 0xB0))
			vehForeign.ecx = *(*uint32)(unsafe.Pointer(ctx + 0xAC))
			vehForeign.eip = eip
			if vehForeignStub != 0 {
				*(*uint32)(unsafe.Pointer(ctx + 0xB8)) = vehForeignStub
				return 0xFFFFFFFF // EXCEPTION_CONTINUE_EXECUTION
			}
		}
		return 0
	}

	lastVEH.code = r.Code
	lastVEH.addr = uint32(r.Address)
	if r.NumParams >= 2 {
		lastVEH.access = uint32(r.Info[1])
	}
	lastVEH.caught = true
	if ep.Context != 0 {
		ctx := ep.Context
		lastVEH.eax = *(*uint32)(unsafe.Pointer(ctx + 0xB0))
		lastVEH.ecx = *(*uint32)(unsafe.Pointer(ctx + 0xAC))
		lastVEH.edx = *(*uint32)(unsafe.Pointer(ctx + 0xA8))
		lastVEH.ebx = *(*uint32)(unsafe.Pointer(ctx + 0xA4))
		lastVEH.esi = *(*uint32)(unsafe.Pointer(ctx + 0xA0))
		lastVEH.edi = *(*uint32)(unsafe.Pointer(ctx + 0x9C))
		lastVEH.ebp = *(*uint32)(unsafe.Pointer(ctx + 0xB4))
		lastVEH.esp = *(*uint32)(unsafe.Pointer(ctx + 0xC4))

		vehStackSnapN = 0
		if lastVEH.esp > 0x10000 {
			var mbi memoryBasicInformation
			rq, _, _ := syscall.SyscallN(addrVirtualQuery, uintptr(lastVEH.esp), uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
			if rq != 0 && mbi.State == 0x1000 && (mbi.Protect&0xFF) != 0x01 && (mbi.Protect&0x100) == 0 {
				end := mbi.BaseAddress + mbi.RegionSize
				n := 0
				for addr := uintptr(lastVEH.esp); addr >= mbi.BaseAddress && addr+4 <= end && n < len(vehStackSnapshot); addr += 4 {
					vehStackSnapshot[n] = *(*uint32)(unsafe.Pointer(addr))
					n++
				}
				vehStackSnapN = n
			}
		}

		vehFrameSnapN = 0
		if lastVEH.ebp > 0x10000 {
			var mbi2 memoryBasicInformation
			rq2, _, _ := syscall.SyscallN(addrVirtualQuery, uintptr(lastVEH.ebp), uintptr(unsafe.Pointer(&mbi2)), unsafe.Sizeof(mbi2))
			if rq2 != 0 && mbi2.State == 0x1000 && (mbi2.Protect&0xFF) != 0x01 && (mbi2.Protect&0x100) == 0 {
				end2 := mbi2.BaseAddress + mbi2.RegionSize
				n2 := 0
				for off := -0x38; off <= 0x14 && n2 < len(vehFrameSnap); off += 4 {
					a := uintptr(int32(lastVEH.ebp) + int32(off))
					if a < mbi2.BaseAddress || a+4 > end2 {
						continue
					}
					vehFrameSnap[n2] = *(*uint32)(unsafe.Pointer(a))
					n2++
				}
				vehFrameSnapN = n2
			}
		}
	}
	if vehRecoverAt != 0 && ep.Context != 0 {
		*(*uint32)(unsafe.Pointer(ep.Context + 0xB8)) = vehRecoverAt
		return 0xFFFFFFFF // EXCEPTION_CONTINUE_EXECUTION
	}
	return 0
})

var errCallTimeout = errors.New("原生线程调用超时")

type threadTimeoutError struct {
	msg string
}

func (e *threadTimeoutError) Error() string { return e.msg }
func (e *threadTimeoutError) Unwrap() error { return errCallTimeout }

// callOnThread 默认 20s 超时
func callOnThread(fn uintptr, args ...uintptr) (uint32, error) {
	return callOnThreadTO(fn, 20000, args...)
}

var vehRecoverAt uint32
var imgBase, imgSize uint32

// callOnThreadTO 在 Windows 原生线程里以 stdcall 执行 fn(args...) (≤4 参数)。
func callOnThreadTO(fn uintptr, timeoutMs uintptr, args ...uintptr) (uint32, error) {
	initWin32Procs()

	pg, _, _ := procVirtualAlloc.Call(0, 0x1000, 0x3000, 0x40) // RWX
	if pg == 0 {
		return 0, errors.New("桩页分配失败")
	}
	timedOut := false
	defer func() {
		atomic.StoreUintptr(&vehStubBase, 0)
		if !timedOut {
			k32Free(pg, 0)
		}
	}()
	atomic.StoreUintptr(&vehStubBase, pg)

	resPtr := pg + 0x100
	codePtr := pg + 0x200
	c := unsafe.Slice((*byte)(unsafe.Pointer(codePtr)), 0x200)
	var code []byte
	for i := len(args) - 1; i >= 0; i-- {
		code = append(code, 0x68) // push imm32
		var a [4]byte
		binary.LittleEndian.PutUint32(a[:], uint32(args[i]))
		code = append(code, a[:]...)
	}
	callAt := len(code)
	code = append(code, 0xE8, 0, 0, 0, 0)
	code = append(code, 0xA3) // mov [resPtr], eax
	var r [4]byte
	binary.LittleEndian.PutUint32(r[:], uint32(resPtr))
	code = append(code, r[:]...)
	code = append(code, 0x6A, 0x00) // push 0
	code = append(code, 0xB8)       // mov eax, ExitThread
	var e4 [4]byte
	binary.LittleEndian.PutUint32(e4[:], uint32(addrExitThread))
	code = append(code, e4[:]...)
	code = append(code, 0xFF, 0xD0) // call eax
	copy(c, code)
	binary.LittleEndian.PutUint32(c[callAt+1:callAt+5], uint32(fn-codePtr-uintptr(callAt+5)))

	rop := pg + 0x300
	rc := unsafe.Slice((*byte)(unsafe.Pointer(rop)), 0x80)
	var rec []byte
	rec = append(rec, 0xBC) // mov esp, pg+0xF00
	var rs [4]byte
	binary.LittleEndian.PutUint32(rs[:], uint32(pg+0xF00))
	rec = append(rec, rs[:]...)
	rec = append(rec, 0xC7, 0x05) // mov dword [resPtr], 0
	var rr [4]byte
	binary.LittleEndian.PutUint32(rr[:], uint32(resPtr))
	rec = append(rec, rr[:]...)
	rec = append(rec, 0, 0, 0, 0)
	rec = append(rec, 0x6A, 0x00)
	rec = append(rec, 0xB8)
	rec = append(rec, e4[:]...)
	rec = append(rec, 0xFF, 0xD0)
	copy(rc, rec)
	vehRecoverAt = uint32(rop)

	lastVEH.caught = false
	atomic.StoreInt32(&vehForeign.count, 0)
	if vehForeignStub == 0 {
		fpg, _, _ := procVirtualAlloc.Call(0, 0x1000, 0x3000, 0x40)
		if fpg != 0 {
			fc := unsafe.Slice((*byte)(unsafe.Pointer(fpg)), 0x1000)
			var fstub []byte
			fstub = append(fstub, 0xBC)
			var fe0 [4]byte
			binary.LittleEndian.PutUint32(fe0[:], uint32(fpg+0xF00))
			fstub = append(fstub, fe0[:]...)
			fstub = append(fstub, 0x6A, 0x00)
			fstub = append(fstub, 0xB8)
			fstub = append(fstub, e4[:]...)
			fstub = append(fstub, 0xFF, 0xD0)
			copy(fc, fstub)
			vehForeignStub = uint32(fpg)
		}
	}

	hVEH, _, _ := procAddVEH.Call(1, vehCallback)
	if hVEH != 0 {
		defer procRemoveVEH.Call(hVEH)
	}

	var tid uint32
	// CREATE_SUSPENDED (0x4): 先写入 vehCodeThreadID 再 ResumeThread，彻底消除启动竞态
	hT, _, _ := procCreateThread.Call(0, 0, codePtr, 0, 0x4, uintptr(unsafe.Pointer(&tid)))
	if hT == 0 {
		return 0, errors.New("CreateThread 失败")
	}
	defer procCloseHandle.Call(hT)
	atomic.StoreUint32(&vehCodeThreadID, tid)
	defer atomic.StoreUint32(&vehCodeThreadID, 0)
	procResumeThread.Call(hT)

	wr, _, _ := procWaitForSingleObj.Call(hT, timeoutMs)
	if wr == 258 {
		timedOut = true
		ib := atomic.LoadUint32(&imgBase)
		is := atomic.LoadUint32(&imgSize)
		msg := fmt.Sprintf("原生线程调用超时 (%dms)", timeoutMs)
		if fc := atomic.LoadInt32(&vehForeign.count); fc > 0 {
			msg += fmt.Sprintf(" | 外来线程崩溃×%d (tid=%d eip=RVA 0x%x 崩溃地址=0x%x eax=0x%x ecx=0x%x)",
				fc, vehForeign.threadID, vehForeign.eip-ib, vehForeign.addr, vehForeign.eax, vehForeign.ecx)
		}
		if s, _, _ := procSuspendThread.Call(hT); s != 0xFFFFFFFF {
			cbuf := make([]byte, 0x2D0+16)
			cp := uintptr(unsafe.Pointer(&cbuf[0]))
			cp = (cp + 15) &^ 15
			c := (*[0x2CC / 4]uint32)(unsafe.Pointer(cp))
			c[0] = 0x10007 // CONTEXT_i386|CONTROL|INTEGER
			if ok, _, _ := procGetThreadContext.Call(hT, cp); ok != 0 {
				eip, esp, ebp := c[0xB8/4], c[0xC4/4], c[0xB4/4]
				if eip >= ib && eip < ib+is {
					msg += fmt.Sprintf(" | 卡点 EIP=RVA 0x%x (esp=0x%x ebp=0x%x)", eip-ib, esp, ebp)
				} else {
					msg += fmt.Sprintf(" | 卡点 EIP=0x%x (镜像外 API 内)", eip)
				}
				if esp > 0x10000 {
					var mbi memoryBasicInformation
					rq, _, _ := procVirtualQuery.Call(uintptr(esp), uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
					if rq != 0 && mbi.State == 0x1000 && (mbi.Protect&0xFF) != 0x01 && (mbi.Protect&0x100) == 0 {
						end := mbi.BaseAddress + mbi.RegionSize
						chain := ""
						n := 0
						for a := uintptr(esp); a >= mbi.BaseAddress && a+4 <= end && n < 40; a, n = a+4, n+1 {
							v := *(*uint32)(unsafe.Pointer(a))
							if v >= ib && v < ib+is {
								chain += fmt.Sprintf(" [+%d→0x%x]", a-uintptr(esp), v-ib)
								if len(chain) > 300 {
									break
								}
							}
						}
						if chain != "" {
							msg += " | 卡点栈链:" + chain
						}
					}
				}
			}
			runtime.KeepAlive(cbuf)
			procResumeThread.Call(hT)
		}
		return 0, &threadTimeoutError{msg: msg}
	}

	if lastVEH.caught {
		ib := atomic.LoadUint32(&imgBase)
		is := atomic.LoadUint32(&imgSize)
		msg := fmt.Sprintf("★目标代码异常: code=0x%x 崩溃@0x%x 访问=0x%x | eax=0x%08x ecx=0x%08x edx=0x%08x ebx=0x%08x esi=0x%08x edi=0x%08x ebp=0x%08x esp=0x%08x",
			lastVEH.code, lastVEH.addr, lastVEH.access,
			lastVEH.eax, lastVEH.ecx, lastVEH.edx, lastVEH.ebx,
			lastVEH.esi, lastVEH.edi, lastVEH.ebp, lastVEH.esp)
		if ib != 0 && is != 0 {
			chain := ""
			for k := 0; k < vehStackSnapN; k++ {
				v := vehStackSnapshot[k]
				if v >= ib && v < ib+is {
					chain += fmt.Sprintf(" [esp+%d→RVA 0x%x]", 4*k, v-ib)
					if len(chain) > 360 {
						break
					}
				}
			}
			if chain != "" {
				msg += " | 栈链:" + chain
			}
		}
		if vehFrameSnapN > 0 {
			fr := " | 帧:"
			for k := 0; k < vehFrameSnapN; k++ {
				off := -0x38 + 4*k
				fr += fmt.Sprintf(" [ebp%+d]=0x%08x", off, vehFrameSnap[k])
			}
			msg += fr
		}
		return 0, fmt.Errorf("%s", msg)
	}
	var ec uint32
	procGetExitCodeThread.Call(hT, uintptr(unsafe.Pointer(&ec)))
	res := le32(unsafe.Slice((*byte)(unsafe.Pointer(pg)), 0x1000), 0x100)
	if ec != 0 {
		return 0, fmt.Errorf("线程退出码 0x%x", ec)
	}
	return res, nil
}

func funcName(mem []byte, thunk uint32) string {
	if thunk&0x80000000 != 0 {
		return fmt.Sprintf("ord%d", thunk&0xFFFF)
	}
	if thunk+2 >= uint32(len(mem)) {
		return "?"
	}
	return cstrInMem(mem, thunk+2, uint32(len(mem)))
}

// k32Free 释放 VirtualAlloc 分配的内存 (MEM_RELEASE 时 dwSize 必须为 0)
func k32Free(base uintptr, size uint32) {
	if base == 0 {
		return
	}
	initWin32Procs()
	procVirtualFree.Call(base, 0, 0x8000)
}
