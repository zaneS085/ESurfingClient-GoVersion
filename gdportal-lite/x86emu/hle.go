package x86emu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type hleEntry struct {
	name     string
	stdcall  bool
	argCount int
	fn       func(h *hleEnv, c *CPU) uint32
}

type hleEnv struct {
	mem                *Mem
	cpu                *CPU
	stubs              []hleEntry
	byKey              map[string]uint32
	stubAddr           map[string]uint32
	fakeInnerObjAddr   uint32
	lastErr            uint32
	randSeed           uint32
	lastRoutedIP       uint32
	ws2InetAddrStub    uint32
	ws2SocketStub      uint32
	ws2CloseSocketStub uint32
	ws2IoctlStub       uint32
}

func newHLEEnv(mem *Mem) *hleEnv {
	h := &hleEnv{
		mem:      mem,
		stubs:    make([]hleEntry, 1, 128), // index 0 unused
		byKey:    make(map[string]uint32),
		stubAddr: make(map[string]uint32),
		randSeed: 1,
	}
	h.registerBuiltins()
	return h
}

func (h *hleEnv) arg(i int) uint32 {
	v, _ := h.mem.Read32(h.cpu.R[regESP] + 4 + uint32(i)*4)
	return v
}

func (h *hleEnv) register(name string, stdcall bool, argCount int, fn func(*hleEnv, *CPU) uint32) uint32 {
	if addr, ok := h.stubAddr[name]; ok {
		return addr
	}
	id := uint32(len(h.stubs))
	h.stubs = append(h.stubs, hleEntry{name: name, stdcall: stdcall, argCount: argCount, fn: fn})
	addr := StubBase + id*4
	h.stubAddr[name] = addr
	return addr
}

func (h *hleEnv) resolveImport(dllName, fnName string) uint32 {
	key := strings.ToLower(dllName) + "!" + fnName
	if addr, ok := h.byKey[key]; ok {
		return addr
	}
	if addr, ok := h.stubAddr[fnName]; ok {
		h.byKey[key] = addr
		return addr
	}
	// 默认未知函数: 安全无副作用占位存根
	stdcall := strings.HasSuffix(strings.ToLower(dllName), ".dll") &&
		!strings.HasPrefix(strings.ToLower(dllName), "vcruntime") &&
		!strings.HasPrefix(strings.ToLower(dllName), "api-ms-win-crt") &&
		!strings.HasPrefix(strings.ToLower(dllName), "msvcrt")
	addr := h.register(key, stdcall, 0, func(*hleEnv, *CPU) uint32 { return 0 })
	h.byKey[key] = addr
	return addr
}

func (h *hleEnv) dispatch(id uint32) error {
	if int(id) <= 0 || int(id) >= len(h.stubs) {
		return fmt.Errorf("unknown HLE stub #%d", id)
	}
	ent := h.stubs[id]
	retAddr, err := h.cpu.Pop32()
	if err != nil {
		return err
	}
	// arg(i) expects ESP BEFORE Pop32 — compensate by adjusting ESP back temporarily
	h.cpu.R[regESP] -= 4
	res := ent.fn(h, h.cpu)
	h.cpu.R[regESP] += 4
	if h.cpu.Exited {
		return ErrExitThread
	}
	if ent.stdcall && ent.argCount > 0 {
		h.cpu.R[regESP] += uint32(ent.argCount) * 4
	}
	h.cpu.R[regEAX] = res
	h.cpu.EIP = retAddr
	return nil
}

func (h *hleEnv) initFakeInnerObj() uint32 {
	if h.fakeInnerObjAddr != 0 {
		return h.fakeInnerObjAddr
	}
	vtbl := h.mem.Alloc(0x100, true)
	obj := h.mem.Alloc(0x400, true)
	stub := h.register("InnerObjMethodStub", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	for i := uint32(0); i < 32; i++ {
		_ = h.mem.Write32(vtbl+i*4, stub)
	}
	_ = h.mem.Write32(obj, vtbl)
	h.fakeInnerObjAddr = obj
	return obj
}

func (h *hleEnv) registerBuiltins() {
	const handleInnerDSAssist = 1
	const handleKernel32 = 0x10000001

	// ---- InnerDSAssist virtual exports (stdcall, 复刻 Svr ord4/5/9/10 + factory) ----
	ord4Addr := h.register("InnerDSAssist!ord#4", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		ln := h.arg(0)
		blk := h.mem.Alloc(64+ln, true)
		if blk == 0 {
			return 0
		}
		_ = h.mem.Write32(blk+4, ln)
		_ = h.mem.Write32(blk+8, blk+16)
		return blk
	})
	ord5Addr := h.register("InnerDSAssist!ord#5", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		strPtr := h.arg(0)
		if strPtr == 0 {
			return 0
		}
		s := strings.TrimSpace(h.mem.ReadCStr(strPtr, 1<<20))
		data, err := hex.DecodeString(s)
		if err != nil || len(data) == 0 {
			return 0
		}
		n := uint32(len(data))
		blk := h.mem.Alloc(64+n+1, true)
		if blk == 0 {
			return 0
		}
		_ = h.mem.Write32(blk+4, n)
		_ = h.mem.Write32(blk+8, blk+16)
		_ = h.mem.WriteBytes(blk+16, data)
		_ = h.mem.Write8(blk+16+n, 0)
		return blk
	})
	ord9Addr := h.register("InnerDSAssist!ord#9", true, 2, func(h *hleEnv, _ *CPU) uint32 {
		dp := h.arg(0)
		ln := h.arg(1)
		if dp == 0 || ln == 0 || ln > 1<<20 {
			return 0
		}
		src, err := h.mem.ReadBytes(dp, ln)
		if err != nil {
			return 0
		}
		hexStr := strings.ToUpper(hex.EncodeToString(src))
		blk := h.mem.Alloc(uint32(len(hexStr))+16, true)
		if blk == 0 {
			return 0
		}
		_ = h.mem.WriteCStr(blk, hexStr)
		return blk
	})
	ord10Addr := h.register("InnerDSAssist!ord#10", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		p := h.arg(0)
		if p == 0 {
			return 0
		}
		s := h.mem.ReadCStr(p, 65536)
		return h.mem.AllocCStr(s)
	})
	fakeFactoryAddr := h.register("InnerDSAssist!Factory", true, 2, func(h *hleEnv, _ *CPU) uint32 {
		return h.initFakeInnerObj()
	})

	// ---- Ws2_32.dll PE 导出表专用存根 (供 0x10005fb0 本机出口探测保存真实 ipv4) ----
	h.ws2InetAddrStub = h.register("ws2_inet_addr", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		ip := net.ParseIP(h.mem.ReadCStr(h.arg(0), 64)).To4()
		if ip == nil {
			return 0xFFFFFFFF
		}
		return binary.LittleEndian.Uint32(ip)
	})
	h.ws2SocketStub = h.register("ws2_socket", true, 3, func(*hleEnv, *CPU) uint32 { return 0x1001 })
	h.ws2CloseSocketStub = h.register("ws2_closesocket", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.ws2IoctlStub = h.register("ws2_WSAIoctl", true, 9, func(h *hleEnv, _ *CPU) uint32 {
		code := h.arg(1)
		inBuf := h.arg(2)
		inLen := h.arg(3)
		outBuf := h.arg(4)
		outLen := h.arg(5)
		cbRet := h.arg(6)
		switch code {
		case 0xC8000014: // SIO_ROUTING_INTERFACE_QUERY
			if inBuf != 0 && inLen >= 16 && outBuf != 0 && outLen >= 16 {
				if b, err := h.mem.ReadBytes(inBuf, 16); err == nil {
					_ = h.mem.WriteBytes(outBuf, b)
				}
				if ip, err := h.mem.Read32(inBuf + 4); err == nil && ip != 0 {
					h.lastRoutedIP = ip
				}
				if cbRet != 0 {
					_ = h.mem.Write32(cbRet, 16)
				}
				return 0
			}
		case 0x48000016: // SIO_ADDRESS_LIST_QUERY
			if outBuf != 0 && outLen >= 32 {
				ip := h.lastRoutedIP
				if ip == 0 {
					ip = 0x0100007F
				}
				_ = h.mem.Write32(outBuf+0, 1) // iAddressCount
				_ = h.mem.Write32(outBuf+4, outBuf+16)
				_ = h.mem.Write32(outBuf+8, 16)
				_ = h.mem.Write16(outBuf+16, 2) // AF_INET
				_ = h.mem.Write16(outBuf+18, 0)
				_ = h.mem.Write32(outBuf+20, ip)
				if cbRet != 0 {
					_ = h.mem.Write32(cbRet, 32)
				}
				return 0
			}
		}
		return 0xFFFFFFFF
	})

	// ---- kernel32.dll ----
	h.register("GetProcessHeap", true, 0, func(*hleEnv, *CPU) uint32 { return 1 })
	h.register("HeapAlloc", true, 3, func(h *hleEnv, _ *CPU) uint32 {
		flags := h.arg(1)
		sz := h.arg(2)
		return h.mem.Alloc(sz, flags&8 != 0)
	})
	h.register("HeapFree", true, 3, func(h *hleEnv, _ *CPU) uint32 {
		h.mem.Free(h.arg(2))
		return 1
	})
	h.register("LoadLibraryA", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		name := strings.ToLower(h.mem.ReadCStr(h.arg(0), 260))
		if strings.Contains(name, "innerdsassist") {
			return handleInnerDSAssist
		}
		if strings.Contains(name, "kernel32") {
			return handleKernel32
		}
		if strings.Contains(name, "ws2_32") {
			return Ws2Base
		}
		return 0
	})
	h.register("LoadLibraryW", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		name := strings.ToLower(h.mem.ReadWStrASCII(h.arg(0), 260))
		if strings.Contains(name, "innerdsassist") {
			return handleInnerDSAssist
		}
		if strings.Contains(name, "kernel32") {
			return handleKernel32
		}
		if strings.Contains(name, "ws2_32") {
			return Ws2Base
		}
		return 0
	})
	h.register("GetModuleHandleA", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		p := h.arg(0)
		if p == 0 {
			return h.mem.imgBase
		}
		name := strings.ToLower(h.mem.ReadCStr(p, 260))
		if strings.Contains(name, "innerdsassist") {
			return handleInnerDSAssist
		}
		if strings.Contains(name, "kernel32") {
			return handleKernel32
		}
		if strings.Contains(name, "ws2_32") {
			return Ws2Base
		}
		return 0
	})
	h.register("GetModuleHandleW", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		p := h.arg(0)
		if p == 0 {
			return h.mem.imgBase
		}
		name := strings.ToLower(h.mem.ReadWStrASCII(p, 260))
		if strings.Contains(name, "innerdsassist") {
			return handleInnerDSAssist
		}
		if strings.Contains(name, "kernel32") {
			return handleKernel32
		}
		if strings.Contains(name, "ws2_32") {
			return Ws2Base
		}
		return 0
	})
	h.register("FreeLibrary", true, 1, func(*hleEnv, *CPU) uint32 { return 1 })
	h.register("GetProcAddress", true, 2, func(h *hleEnv, _ *CPU) uint32 {
		hmod := h.arg(0)
		name := h.arg(1)
		if hmod == Ws2Base && name >= 0x10000 {
			switch h.mem.ReadCStr(name, 128) {
			case "socket":
				return h.ws2SocketStub
			case "closesocket":
				return h.ws2CloseSocketStub
			case "inet_addr":
				return h.ws2InetAddrStub
			case "WSAIoctl":
				return h.ws2IoctlStub
			}
			return 0
		}
		if hmod == handleInnerDSAssist {
			switch name {
			case 4:
				return ord4Addr
			case 5:
				return ord5Addr
			case 9:
				return ord9Addr
			case 10:
				return ord10Addr
			}
			if name >= 0x10000 {
				return fakeFactoryAddr
			}
			return 0
		}
		if hmod == handleKernel32 && name >= 0x10000 {
			fn := h.mem.ReadCStr(name, 128)
			if addr, ok := h.stubAddr[fn]; ok {
				return addr
			}
		}
		return 0
	})
	h.register("CreateThread", true, 6, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("CloseHandle", true, 1, func(*hleEnv, *CPU) uint32 { return 1 })
	h.register("WaitForSingleObject", true, 2, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("ExitThread", true, 1, func(_ *hleEnv, c *CPU) uint32 {
		c.Exited = true
		return 0
	})
	h.register("TerminateThread", true, 2, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("InitializeCriticalSection", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("InitializeCriticalSectionEx", true, 3, func(*hleEnv, *CPU) uint32 { return 1 })
	h.register("EnterCriticalSection", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("LeaveCriticalSection", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("DeleteCriticalSection", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("InitializeSListHead", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		if p := h.arg(0); p != 0 {
			_ = h.mem.Fill(p, 8, 0)
		}
		return 0
	})
	h.register("GetTickCount", true, 0, func(*hleEnv, *CPU) uint32 {
		return uint32(time.Now().UnixMilli() & 0x7FFFFFFF)
	})
	h.register("QueryPerformanceCounter", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		if p := h.arg(0); p != 0 {
			v := uint64(time.Now().UnixNano())
			_ = h.mem.Write32(p, uint32(v))
			_ = h.mem.Write32(p+4, uint32(v>>32))
		}
		return 1
	})
	h.register("GetSystemTimeAsFileTime", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		if p := h.arg(0); p != 0 {
			// Windows FILETIME: 100ns since 1601-01-01
			ft := uint64(time.Now().UnixNano()/100) + 116444736000000000
			_ = h.mem.Write32(p, uint32(ft))
			_ = h.mem.Write32(p+4, uint32(ft>>32))
		}
		return 0
	})
	h.register("GetCurrentThreadId", true, 0, func(*hleEnv, *CPU) uint32 { return 1001 })
	h.register("GetCurrentProcessId", true, 0, func(*hleEnv, *CPU) uint32 { return 2002 })
	h.register("GetCurrentProcess", true, 0, func(*hleEnv, *CPU) uint32 { return 0xFFFFFFFF })
	h.register("GetLastError", true, 0, func(h *hleEnv, _ *CPU) uint32 { return h.lastErr })
	h.register("IsDebuggerPresent", true, 0, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("IsProcessorFeaturePresent", true, 1, func(h *hleEnv, _ *CPU) uint32 {
		switch h.arg(0) {
		case 6, 10, 12, 13, 17, 23: // MMX / XMMI / SSE2 / RDTSC / CompareExchange64 / FastFail
			return 1
		}
		return 0
	})
	h.register("SetUnhandledExceptionFilter", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("UnhandledExceptionFilter", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("TerminateProcess", true, 2, func(_ *hleEnv, c *CPU) uint32 {
		c.Exited = true
		return 1
	})
	h.register("OutputDebugStringW", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("MultiByteToWideChar", true, 6, func(h *hleEnv, _ *CPU) uint32 {
		srcPtr := h.arg(2)
		cbSrc := int32(h.arg(3))
		dstPtr := h.arg(4)
		cchDst := int32(h.arg(5))
		var src string
		if cbSrc == -1 {
			src = h.mem.ReadCStr(srcPtr, 65536)
		} else if cbSrc > 0 {
			b, _ := h.mem.ReadBytes(srcPtr, uint32(cbSrc))
			src = string(b)
		}
		var u16 []uint16
		for len(src) > 0 {
			r, sz := utf8.DecodeRuneInString(src)
			src = src[sz:]
			if r <= 0xFFFF {
				u16 = append(u16, uint16(r))
			} else {
				u16 = append(u16, 0xFFFD)
			}
		}
		if cbSrc == -1 {
			u16 = append(u16, 0)
		}
		if cchDst == 0 || dstPtr == 0 {
			return uint32(len(u16))
		}
		n := len(u16)
		if int32(n) > cchDst {
			n = int(cchDst)
		}
		for i := 0; i < n; i++ {
			_ = h.mem.Write16(dstPtr+uint32(i)*2, u16[i])
		}
		return uint32(n)
	})

	// ---- vcruntime140.dll (cdecl) ----
	h.register("memcpy", false, 3, func(h *hleEnv, _ *CPU) uint32 {
		dst, src, n := h.arg(0), h.arg(1), h.arg(2)
		if n > 0 {
			if b, err := h.mem.ReadBytes(src, n); err == nil {
				_ = h.mem.WriteBytes(dst, b)
			}
		}
		return dst
	})
	h.register("memmove", false, 3, func(h *hleEnv, _ *CPU) uint32 {
		dst, src, n := h.arg(0), h.arg(1), h.arg(2)
		if n > 0 {
			if b, err := h.mem.ReadBytes(src, n); err == nil {
				_ = h.mem.WriteBytes(dst, b)
			}
		}
		return dst
	})
	h.register("memset", false, 3, func(h *hleEnv, _ *CPU) uint32 {
		dst, val, n := h.arg(0), byte(h.arg(1)), h.arg(2)
		_ = h.mem.Fill(dst, n, val)
		return dst
	})
	h.register("strchr", false, 2, func(h *hleEnv, _ *CPU) uint32 {
		p := h.arg(0)
		ch := byte(h.arg(1))
		for i := uint32(0); i < 1<<20; i++ {
			b, err := h.mem.Read8(p + i)
			if err != nil {
				return 0
			}
			if b == ch {
				return p + i
			}
			if b == 0 {
				return 0
			}
		}
		return 0
	})
	h.register("strstr", false, 2, func(h *hleEnv, _ *CPU) uint32 {
		p1 := h.arg(0)
		p2 := h.arg(1)
		s1 := h.mem.ReadCStr(p1, 1<<20)
		s2 := h.mem.ReadCStr(p2, 4096)
		idx := strings.Index(s1, s2)
		if idx < 0 {
			return 0
		}
		return p1 + uint32(idx)
	})
	h.register("__CxxFrameHandler3", false, 4, func(*hleEnv, *CPU) uint32 { return 1 })
	h.register("_except_handler4_common", false, 6, func(*hleEnv, *CPU) uint32 { return 1 })
	h.register("__std_type_info_destroy_list", false, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("__std_exception_copy", false, 2, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("__std_exception_destroy", false, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("__std_terminate", false, 0, func(_ *hleEnv, c *CPU) uint32 {
		c.Exited = true
		return 1
	})
	h.register("_CxxThrowException", true, 2, func(_ *hleEnv, c *CPU) uint32 {
		c.Exited = true
		return 1
	})

	// ---- api-ms-win-crt-heap-l1-1-0.dll (cdecl) ----
	h.register("malloc", false, 1, func(h *hleEnv, _ *CPU) uint32 { return h.mem.Alloc(h.arg(0), false) })
	h.register("free", false, 1, func(h *hleEnv, _ *CPU) uint32 { h.mem.Free(h.arg(0)); return 0 })
	h.register("realloc", false, 2, func(h *hleEnv, _ *CPU) uint32 { return h.mem.Realloc(h.arg(0), h.arg(1)) })
	h.register("_callnewh", false, 1, func(*hleEnv, *CPU) uint32 { return 0 })

	// ---- api-ms-win-crt-string-l1-1-0.dll (cdecl) ----
	h.register("_strdup", false, 1, func(h *hleEnv, _ *CPU) uint32 {
		p := h.arg(0)
		if p == 0 {
			return 0
		}
		return h.mem.AllocCStr(h.mem.ReadCStr(p, 1<<20))
	})
	h.register("isalpha", false, 1, func(h *hleEnv, _ *CPU) uint32 {
		c := byte(h.arg(0))
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return 1
		}
		return 0
	})
	h.register("isspace", false, 1, func(h *hleEnv, _ *CPU) uint32 {
		switch byte(h.arg(0)) {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			return 1
		}
		return 0
	})
	h.register("tolower", false, 1, func(h *hleEnv, _ *CPU) uint32 {
		c := h.arg(0)
		if c >= 'A' && c <= 'Z' {
			return c + 32
		}
		return c
	})
	h.register("strncmp", false, 3, func(h *hleEnv, _ *CPU) uint32 {
		p1, p2, n := h.arg(0), h.arg(1), h.arg(2)
		for i := uint32(0); i < n; i++ {
			a, _ := h.mem.Read8(p1 + i)
			b, _ := h.mem.Read8(p2 + i)
			if a != b {
				if a < b {
					return 0xFFFFFFFF
				}
				return 1
			}
			if a == 0 {
				return 0
			}
		}
		return 0
	})
	h.register("strncpy", false, 3, func(h *hleEnv, _ *CPU) uint32 {
		dst, src, n := h.arg(0), h.arg(1), h.arg(2)
		ended := false
		for i := uint32(0); i < n; i++ {
			var b byte
			if !ended {
				b, _ = h.mem.Read8(src + i)
				if b == 0 {
					ended = true
				}
			}
			_ = h.mem.Write8(dst+i, b)
		}
		return dst
	})
	h.register("strspn", false, 2, func(h *hleEnv, _ *CPU) uint32 {
		s := h.mem.ReadCStr(h.arg(0), 65536)
		accept := h.mem.ReadCStr(h.arg(1), 1024)
		for i := 0; i < len(s); i++ {
			if strings.IndexByte(accept, s[i]) < 0 {
				return uint32(i)
			}
		}
		return uint32(len(s))
	})
	h.register("strcspn", false, 2, func(h *hleEnv, _ *CPU) uint32 {
		s := h.mem.ReadCStr(h.arg(0), 65536)
		reject := h.mem.ReadCStr(h.arg(1), 1024)
		for i := 0; i < len(s); i++ {
			if strings.IndexByte(reject, s[i]) >= 0 {
				return uint32(i)
			}
		}
		return uint32(len(s))
	})

	// ---- api-ms-win-crt-convert-l1-1-0.dll (cdecl) ----
	h.register("strtol", false, 3, func(h *hleEnv, _ *CPU) uint32 {
		nptr := h.arg(0)
		endptr := h.arg(1)
		base := int(int32(h.arg(2)))
		s := h.mem.ReadCStr(nptr, 4096)
		val, consumed := cStrtol(s, base)
		if endptr != 0 {
			_ = h.mem.Write32(endptr, nptr+uint32(consumed))
		}
		return uint32(val)
	})

	// ---- api-ms-win-crt-stdio-l1-1-0.dll (cdecl) ----
	// int __stdio_common_vsprintf(uint64 options, char* buf, size_t bufCount, char* fmt, _locale_t loc, va_list va)
	// options occupies arg(0)+arg(1)!
	h.register("__stdio_common_vsprintf", false, 7, func(h *hleEnv, _ *CPU) uint32 {
		buf := h.arg(2)
		bufCount := h.arg(3)
		fmtPtr := h.arg(4)
		vaPtr := h.arg(6)
		fmtStr := h.mem.ReadCStr(fmtPtr, 65536)
		formatted := h.formatPrintf(fmtStr, vaPtr)
		if buf == 0 || bufCount == 0 {
			return uint32(len(formatted))
		}
		if bufCount == 1 {
			_ = h.mem.Write8(buf, 0)
			return uint32(len(formatted))
		}
		maxWrite := uint64(bufCount) - 1
		toWrite := formatted
		if uint64(len(toWrite)) > maxWrite {
			toWrite = toWrite[:int(maxWrite)]
		}
		_ = h.mem.WriteCStr(buf, toWrite)
		return uint32(len(formatted))
	})

	// ---- api-ms-win-crt-runtime-l1-1-0.dll (cdecl) ----
	initTerm := func(h *hleEnv, c *CPU) uint32 {
		first := h.arg(0)
		last := h.arg(1)
		for p := first; p < last; p += 4 {
			fn, err := h.mem.Read32(p)
			if err != nil {
				break
			}
			if fn != 0 {
				res, cerr := c.Call(fn)
				if cerr != nil && cerr != ErrExitThread {
					break
				}
				_ = res
			}
		}
		return 0
	}
	h.register("_initterm", false, 2, initTerm)
	h.register("_initterm_e", false, 2, initTerm)
	h.register("_initialize_onexit_table", false, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("_register_onexit_function", false, 2, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("_execute_onexit_table", false, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("_crt_atexit", false, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("_cexit", false, 0, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("_configure_narrow_argv", false, 1, func(*hleEnv, *CPU) uint32 { return 0 })
	h.register("_initialize_narrow_environment", false, 0, func(*hleEnv, *CPU) uint32 { return 1 })
	h.register("_seh_filter_dll", false, 2, func(*hleEnv, *CPU) uint32 { return 0 })

	// ---- api-ms-win-crt-utility-l1-1-0.dll ----
	h.register("srand", false, 1, func(h *hleEnv, _ *CPU) uint32 {
		h.randSeed = h.arg(0)
		return 0
	})

	// ---- iphlpapi.dll (stdcall) ----
	h.register("GetAdaptersAddresses", true, 5, func(*hleEnv, *CPU) uint32 { return 111 })
	h.register("GetAdaptersInfo", true, 2, func(*hleEnv, *CPU) uint32 { return 111 })
	h.register("GetBestInterface", true, 2, func(*hleEnv, *CPU) uint32 { return 1 })
	h.register("GetBestRoute", true, 3, func(*hleEnv, *CPU) uint32 { return 1 })

	// ---- ws2_32.dll ordinals (stdcall) ----
	h.register("ws2_32.dll!ord#2", true, 3, func(*hleEnv, *CPU) uint32 { return 0xFFFFFFFF })   // bind
	h.register("ws2_32.dll!ord#3", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })            // closesocket
	h.register("ws2_32.dll!ord#4", true, 3, func(*hleEnv, *CPU) uint32 { return 0xFFFFFFFF })   // connect
	h.register("ws2_32.dll!ord#9", true, 1, func(h *hleEnv, _ *CPU) uint32 {                    // htons
		v := uint16(h.arg(0))
		return uint32((v>>8)|(v<<8))
	})
	h.register("ws2_32.dll!ord#10", true, 1, func(h *hleEnv, _ *CPU) uint32 { // inet_addr
		ip := net.ParseIP(h.mem.ReadCStr(h.arg(0), 64)).To4()
		if ip == nil {
			return 0xFFFFFFFF
		}
		return binary.LittleEndian.Uint32(ip)
	})
	h.register("ws2_32.dll!ord#11", true, 1, func(*hleEnv, *CPU) uint32 { return 0 })          // inet_ntoa
	h.register("ws2_32.dll!ord#16", true, 4, func(*hleEnv, *CPU) uint32 { return 0xFFFFFFFF }) // recv
	h.register("ws2_32.dll!ord#17", true, 6, func(*hleEnv, *CPU) uint32 { return 0xFFFFFFFF }) // recvfrom
	h.register("ws2_32.dll!ord#18", true, 5, func(*hleEnv, *CPU) uint32 { return 0 })          // select
	h.register("ws2_32.dll!ord#19", true, 4, func(*hleEnv, *CPU) uint32 { return 0xFFFFFFFF }) // send
	h.register("ws2_32.dll!ord#21", true, 5, func(*hleEnv, *CPU) uint32 { return 0 })          // setsockopt
	h.register("ws2_32.dll!ord#23", true, 3, func(*hleEnv, *CPU) uint32 { return 0xFFFFFFFF }) // socket
	h.register("ws2_32.dll!ord#111", true, 0, func(*hleEnv, *CPU) uint32 { return 10051 })     // WSAGetLastError
	h.register("ws2_32.dll!ord#151", true, 2, func(*hleEnv, *CPU) uint32 { return 0 })         // __WSAFDIsSet
}

func cStrtol(s string, base int) (int32, int) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\v' || s[i] == '\f') {
		i++
	}
	neg := false
	if i < len(s) {
		if s[i] == '-' {
			neg = true
			i++
		} else if s[i] == '+' {
			i++
		}
	}
	if base == 0 {
		if i+1 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
			base = 16
			i += 2
		} else if i < len(s) && s[i] == '0' {
			base = 8
		} else {
			base = 10
		}
	} else if base == 16 && i+1 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
		i += 2
	}
	if base < 2 || base > 36 {
		return 0, 0
	}
	start := i
	var acc uint64
	for i < len(s) {
		ch := s[i]
		var d int
		switch {
		case ch >= '0' && ch <= '9':
			d = int(ch - '0')
		case ch >= 'a' && ch <= 'z':
			d = int(ch-'a') + 10
		case ch >= 'A' && ch <= 'Z':
			d = int(ch-'A') + 10
		default:
			d = 99
		}
		if d >= base {
			break
		}
		acc = acc*uint64(base) + uint64(d)
		i++
	}
	if i == start {
		return 0, 0
	}
	if neg {
		return -int32(acc), i
	}
	return int32(acc), i
}

func (h *hleEnv) formatPrintf(fmtStr string, vaPtr uint32) string {
	var out strings.Builder
	cur := vaPtr
	readU32 := func() uint32 {
		v, _ := h.mem.Read32(cur)
		cur += 4
		return v
	}
	readU64 := func() uint64 {
		lo, _ := h.mem.Read32(cur)
		hi, _ := h.mem.Read32(cur + 4)
		cur += 8
		return uint64(lo) | (uint64(hi) << 32)
	}

	for i := 0; i < len(fmtStr); i++ {
		if fmtStr[i] != '%' {
			out.WriteByte(fmtStr[i])
			continue
		}
		i++
		if i >= len(fmtStr) {
			break
		}
		if fmtStr[i] == '%' {
			out.WriteByte('%')
			continue
		}
		var leftAlign, zeroPad, plusSign, altForm bool
		for i < len(fmtStr) {
			switch fmtStr[i] {
			case '-':
				leftAlign = true
				i++
				continue
			case '0':
				zeroPad = true
				i++
				continue
			case '+':
				plusSign = true
				i++
				continue
			case '#':
				altForm = true
				i++
				continue
			}
			break
		}
		width := 0
		if i < len(fmtStr) && fmtStr[i] == '*' {
			w := int32(readU32())
			if w < 0 {
				leftAlign = true
				width = int(-w)
			} else {
				width = int(w)
			}
			i++
		} else {
			for i < len(fmtStr) && fmtStr[i] >= '0' && fmtStr[i] <= '9' {
				width = width*10 + int(fmtStr[i]-'0')
				i++
			}
		}
		prec := -1
		if i < len(fmtStr) && fmtStr[i] == '.' {
			i++
			prec = 0
			if i < len(fmtStr) && fmtStr[i] == '*' {
				p := int32(readU32())
				if p >= 0 {
					prec = int(p)
				}
				i++
			} else {
				for i < len(fmtStr) && fmtStr[i] >= '0' && fmtStr[i] <= '9' {
					prec = prec*10 + int(fmtStr[i]-'0')
					i++
				}
			}
		}
		longCount := 0
		for i < len(fmtStr) && (fmtStr[i] == 'l' || fmtStr[i] == 'h' || fmtStr[i] == 'z') {
			if fmtStr[i] == 'l' {
				longCount++
			}
			i++
		}
		if i >= len(fmtStr) {
			break
		}
		spec := fmtStr[i]
		var piece string
		switch spec {
		case 'd', 'i':
			var sv int64
			if longCount >= 2 {
				sv = int64(readU64())
			} else {
				sv = int64(int32(readU32()))
			}
			neg := sv < 0
			var digits string
			if neg {
				digits = strconv.FormatUint(uint64(-sv), 10)
			} else {
				digits = strconv.FormatUint(uint64(sv), 10)
			}
			if prec == 0 && sv == 0 {
				digits = ""
			} else if prec > len(digits) {
				digits = strings.Repeat("0", prec-len(digits)) + digits
			}
			pfx := ""
			if neg {
				pfx = "-"
			} else if plusSign {
				pfx = "+"
			}
			if zeroPad && !leftAlign && prec < 0 && width > len(pfx)+len(digits) {
				digits = strings.Repeat("0", width-len(pfx)-len(digits)) + digits
			}
			piece = pfx + digits
		case 'u':
			var uv uint64
			if longCount >= 2 {
				uv = readU64()
			} else {
				uv = uint64(readU32())
			}
			piece = strconv.FormatUint(uv, 10)
			if prec > len(piece) {
				piece = strings.Repeat("0", prec-len(piece)) + piece
			}
		case 'x', 'X', 'p':
			var uv uint64
			if longCount >= 2 {
				uv = readU64()
			} else {
				uv = uint64(readU32())
			}
			s := strconv.FormatUint(uv, 16)
			if spec == 'X' || spec == 'p' {
				s = strings.ToUpper(s)
			}
			if spec == 'p' && width == 0 {
				prec = 8
			}
			if prec > len(s) {
				s = strings.Repeat("0", prec-len(s)) + s
			}
			pfx := ""
			if altForm && uv != 0 {
				if spec == 'X' {
					pfx = "0X"
				} else {
					pfx = "0x"
				}
			}
			if zeroPad && !leftAlign && prec < 0 && width > len(pfx)+len(s) {
				s = strings.Repeat("0", width-len(pfx)-len(s)) + s
			}
			piece = pfx + s
		case 's':
			p := readU32()
			if p == 0 {
				piece = "(null)"
			} else {
				piece = h.mem.ReadCStr(p, 65536)
			}
			if prec >= 0 && len(piece) > prec {
				piece = piece[:prec]
			}
		case 'c':
			piece = string([]byte{byte(readU32())})
		default:
			piece = "%" + string(spec)
		}

		if width > len(piece) {
			padChar := " "
			if zeroPad && !leftAlign && (spec == 'u') {
				padChar = "0"
			}
			pad := strings.Repeat(padChar, width-len(piece))
			if leftAlign {
				piece += pad
			} else {
				piece = pad + piece
			}
		}
		out.WriteString(piece)
	}
	return out.String()
}
