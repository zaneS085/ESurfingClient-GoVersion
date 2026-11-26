package x86emu

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const patAny = 256

// CodePat / DecPat 为服务端下发算法 DLL 的 Code / DeCode 跨模板函数入口特征
var CodePat = []int{0x55, 0x8b, 0xec, 0x83, 0xec, patAny, 0x53, 0x56, 0x57, 0x74, 0x14, 0x75, 0x12}
var DecPat = []int{0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0x83, 0xec, patAny, 0x53, 0x56, 0x57}

var aesSboxSig = []byte{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5}

const (
	dllPoolRVA   = 0xB088
	dllCfgL1RVA  = 0xB183
	dllCfgOffRVA = 0xB186
	dllCtxRVA    = 0xB5B0
)

func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func le16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func peTextInfo(img []byte) (imageBase, textVA, textROFF, textSize, sizeImage uint32) {
	imageBase = 0x10000000
	textVA = 0x1000
	textROFF = 0x400
	textSize = 0x8000
	sizeImage = 0x10000
	if len(img) < 0x100 || img[0] != 'M' || img[1] != 'Z' {
		return
	}
	e := int(le32(img, 0x3C))
	if e < 0 || e+24+60 > len(img) || string(img[e:e+4]) != "PE\x00\x00" {
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
			if sz := maxU32(vsz, rsz); sz != 0 {
				textSize = sz
			}
			if name == ".text" {
				break
			}
		}
	}
	return
}

// FindFuncRVA 在 PE .text 节中扫描函数特征 RVA
func FindFuncRVA(img []byte, pat []int) (uint32, error) {
	_, textVA, textROFF, textSize, _ := peTextInfo(img)
	lo := int(textROFF)
	hi := lo + int(textSize)
	if lo < 0 || lo >= len(img) {
		lo = 0x400
		hi = lo + 0x8000
	}
	if hi > len(img) {
		hi = len(img)
	}
	for i := lo; i+len(pat) <= hi; i++ {
		ok := true
		for j, p := range pat {
			if p != patAny && int(img[i+j]) != p {
				ok = false
				break
			}
		}
		if ok {
			return textVA + uint32(i-lo), nil
		}
	}
	return 0, errors.New("函数特征未找到")
}

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
	return 0xA000
}

func cstrInSlice(mem []byte, off, limit uint32) string {
	if off >= limit || off >= uint32(len(mem)) {
		return ""
	}
	mx := limit
	if uint32(len(mem)) < mx {
		mx = uint32(len(mem))
	}
	end := off
	for end < mx && mem[end] != 0 {
		end++
	}
	return string(mem[off:end])
}

// PatchAntiTamperCallSite 把 Code/DeCode 内的 PEB 自省防篡改调用点改为恒走成功路径，返回补丁点数
func PatchAntiTamperCallSite(mem []byte, fnRVA, textVA, textEnd uint32) int {
	sig := []byte{0x64, 0xa1, 0x30, 0x00, 0x00, 0x00}
	start, end := int(fnRVA), int(fnRVA)+0x100
	patched := 0
	for i := start; i+13 <= end && i+13 <= len(mem); i++ {
		if mem[i] != 0xE8 {
			continue
		}
		rel := int32(le32(mem, i+1))
		tgt := i + 5 + int(rel)
		if tgt < int(textVA) || tgt >= int(textEnd) || tgt+0x200 > len(mem) {
			continue
		}
		if !bytes.Contains(mem[tgt:tgt+0x200], sig) {
			continue
		}
		if mem[i+5] != 0x85 || mem[i+6] != 0xC0 {
			continue
		}
		j := i + 7
		switch {
		case mem[j] == 0x0F && mem[j+1] == 0x84:
			for k := 0; k < 8; k++ {
				mem[i+5+k] = 0x90
			}
			mem[i+5], mem[i+6] = 0xB0, 0x01
		case mem[j] == 0x0F && mem[j+1] == 0x85:
			mem[i+5], mem[i+6] = 0xB0, 0x01
			mem[j], mem[j+1] = 0x90, 0xE9
		case mem[j] == 0x74:
			for k := 0; k < 4; k++ {
				mem[i+5+k] = 0x90
			}
			mem[i+5], mem[i+6] = 0xB0, 0x01
		case mem[j] == 0x75:
			mem[i+5], mem[i+6] = 0xB0, 0x01
			mem[j] = 0xEB
		default:
			mem[i+5], mem[i+6] = 0xB0, 0x01
		}
		patched++
	}
	return patched
}

// Session 为可复用跨平台纯 Go PE32 算法执行会话
type Session struct {
	mu      sync.Mutex
	mem     *Mem
	hle     *hleEnv
	cpu     *CPU
	codeVA  uint32
	decVA   uint32
	imgBase uint32
}

func NewSession(img []byte, keyhex string) (*Session, error) {
	if len(img) < 0x400 || img[0] != 'M' || img[1] != 'Z' {
		return nil, errors.New("非 PE 镜像")
	}
	e := int(le32(img, 0x3C))
	if e < 0 || e+24+96+44 > len(img) || string(img[e:e+4]) != "PE\x00\x00" {
		return nil, errors.New("非 PE 镜像")
	}
	imageBase := le32(img, e+24+28)
	sizeImage := le32(img, e+24+56)
	nsec := int(le16(img, e+6))
	secOff := e + 24 + int(le16(img, e+20))
	if sizeImage < 0x1000 || sizeImage > 64<<20 || secOff < 0 || secOff+40*nsec > len(img) {
		return nil, errors.New("PE 尺寸或节表越界")
	}

	codeRVA, err := FindFuncRVA(img, CodePat)
	if err != nil {
		return nil, fmt.Errorf("Code: %v", err)
	}
	decRVA, err := FindFuncRVA(img, DecPat)
	if err != nil {
		return nil, fmt.Errorf("DeCode: %v", err)
	}
	kh, err := hex.DecodeString(keyhex)
	if err != nil || len(kh) < 16 {
		return nil, errors.New("keyhex 非法")
	}

	mem := NewMem(imageBase, sizeImage)
	imgSlice := mem.ImageSlice()

	// 复制 PE 头与各节 (.bss 保留零填充)
	hdrCopy := minU32(uint32(len(img)), sizeImage)
	if sizeOfHeaders := le32(img, e+24+60); sizeOfHeaders > 0 && sizeOfHeaders < hdrCopy {
		hdrCopy = sizeOfHeaders
	}
	copy(imgSlice[:hdrCopy], img[:hdrCopy])
	for k := 0; k < nsec; k++ {
		s := img[secOff+40*k : secOff+40*(k+1)]
		va, vsz, roff, rsz := le32(s, 12), le32(s, 8), le32(s, 20), le32(s, 16)
		if roff == 0 || roff >= uint32(len(img)) || va >= sizeImage {
			continue
		}
		cpLen := rsz
		if cpLen == 0 {
			cpLen = vsz
		} else if vsz > 0 && vsz < cpLen {
			cpLen = vsz
		}
		cpLen = minU32(cpLen, uint32(len(img))-roff)
		cpLen = minU32(cpLen, sizeImage-va)
		if cpLen > 0 {
			copy(imgSlice[va:va+cpLen], img[roff:roff+cpLen])
		}
	}

	// 初始化合成 TEB / PEB / PEB_LDR_DATA 与上下文对象页
	_ = mem.Write32(TEBAddr+0x00, 0xFFFFFFFF)
	_ = mem.Write32(TEBAddr+0x04, StackBase+StackSize)
	_ = mem.Write32(TEBAddr+0x08, StackBase)
	_ = mem.Write32(TEBAddr+0x18, TEBAddr)
	_ = mem.Write32(TEBAddr+0x20, 2002)
	_ = mem.Write32(TEBAddr+0x24, 1001)
	_ = mem.Write32(TEBAddr+0x30, PEBAddr)

	const ldrAddr = PEBAddr + 0x100
	const ldrHead = ldrAddr + 0x14 // InMemoryOrderModuleList head
	const mod1Mem = PEBAddr + 0x200
	const mod2Mem = PEBAddr + 0x280
	const mod3Mem = PEBAddr + 0x300
	writeWStr := func(addr uint32, s string) uint16 {
		for i := 0; i < len(s); i++ {
			_ = mem.Write16(addr+uint32(i)*2, uint16(s[i]))
		}
		_ = mem.Write16(addr+uint32(len(s))*2, 0)
		return uint16(len(s) * 2)
	}
	w1 := writeWStr(PEBAddr+0x400, "zxmAlgoic.dll")
	w2 := writeWStr(PEBAddr+0x480, "KERNEL32.DLL")
	w3 := writeWStr(PEBAddr+0x500, "Ws2_32.dll")

	_ = mem.Write32(PEBAddr+0x08, imageBase)
	_ = mem.Write32(PEBAddr+0x0C, ldrAddr)
	_ = mem.Write32(PEBAddr+0x18, HeapBase)

	// 环形链表: ldrHead <-> mod1Mem <-> mod2Mem <-> mod3Mem <-> ldrHead
	_ = mem.Write32(ldrAddr+0x00, 0x2C)
	_ = mem.Write32(ldrAddr+0x04, 1)
	_ = mem.Write32(ldrHead+0x00, mod1Mem)
	_ = mem.Write32(ldrHead+0x04, mod3Mem)

	// mod1Mem (相对 InMemoryOrderLinks: +0x10=DllBase, +0x18=SizeOfImage, +0x1C=FullName, +0x24=BaseName)
	_ = mem.Write32(mod1Mem+0x00, mod2Mem)
	_ = mem.Write32(mod1Mem+0x04, ldrHead)
	_ = mem.Write32(mod1Mem+0x10, imageBase)
	_ = mem.Write32(mod1Mem+0x18, sizeImage)
	_ = mem.Write16(mod1Mem+0x1C, w1)
	_ = mem.Write16(mod1Mem+0x1E, w1+2)
	_ = mem.Write32(mod1Mem+0x20, PEBAddr+0x400)
	_ = mem.Write16(mod1Mem+0x24, w1)
	_ = mem.Write16(mod1Mem+0x26, w1+2)
	_ = mem.Write32(mod1Mem+0x28, PEBAddr+0x400)

	// mod2Mem (KERNEL32.DLL)
	_ = mem.Write32(mod2Mem+0x00, mod3Mem)
	_ = mem.Write32(mod2Mem+0x04, mod1Mem)
	_ = mem.Write32(mod2Mem+0x10, 0x76000000)
	_ = mem.Write32(mod2Mem+0x18, 0x100000)
	_ = mem.Write16(mod2Mem+0x1C, w2)
	_ = mem.Write16(mod2Mem+0x1E, w2+2)
	_ = mem.Write32(mod2Mem+0x20, PEBAddr+0x480)
	_ = mem.Write16(mod2Mem+0x24, w2)
	_ = mem.Write16(mod2Mem+0x26, w2+2)
	_ = mem.Write32(mod2Mem+0x28, PEBAddr+0x480)

	// mod3Mem (Ws2_32.dll @ Ws2Base)
	_ = mem.Write32(mod3Mem+0x00, ldrHead)
	_ = mem.Write32(mod3Mem+0x04, mod2Mem)
	_ = mem.Write32(mod3Mem+0x10, Ws2Base)
	_ = mem.Write32(mod3Mem+0x18, 0x20000)
	_ = mem.Write16(mod3Mem+0x1C, w3)
	_ = mem.Write16(mod3Mem+0x1E, w3+2)
	_ = mem.Write32(mod3Mem+0x20, PEBAddr+0x500)
	_ = mem.Write16(mod3Mem+0x24, w3)
	_ = mem.Write16(mod3Mem+0x26, w3+2)
	_ = mem.Write32(mod3Mem+0x28, PEBAddr+0x500)

	_ = mem.Write32(FakeObjAddr+0x00, CtxPageAddr+0x80)
	_ = mem.Write32(FakeObjAddr+0x04, 1)
	_ = mem.Write8(CtxPageAddr+0x80, 0xC3) // ret

	hle := newHLEEnv(mem)
	// 在 Ws2Base 写入最小 PE32 头与 Export Directory，供手动解析 PEB 导出的样本调用 Ws2_32.dll
	ws := mem.Ws2Slice()
	ws[0], ws[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(ws[0x3C:], 0x40)
	copy(ws[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(ws[0x44:], 0x014C) // Machine = i386
	binary.LittleEndian.PutUint16(ws[0x54:], 0x00E0) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(ws[0x58:], 0x010B) // PE32 magic
	binary.LittleEndian.PutUint32(ws[0x74:], Ws2Base)
	binary.LittleEndian.PutUint32(ws[0x90:], 0x20000) // SizeOfImage
	binary.LittleEndian.PutUint32(ws[0xB8:], 0x100)   // DataDirectory[0] Export RVA
	binary.LittleEndian.PutUint32(ws[0xBC:], 0x100)   // Export Size
	binary.LittleEndian.PutUint32(ws[0x110:], 1)      // Base
	binary.LittleEndian.PutUint32(ws[0x114:], 4)      // NumberOfFunctions
	binary.LittleEndian.PutUint32(ws[0x118:], 4)      // NumberOfNames
	binary.LittleEndian.PutUint32(ws[0x11C:], 0x140)  // AddressOfFunctions
	binary.LittleEndian.PutUint32(ws[0x120:], 0x160)  // AddressOfNames
	binary.LittleEndian.PutUint32(ws[0x124:], 0x170)  // AddressOfNameOrdinals
	wsExports := []struct {
		name string
		stub uint32
	}{
		{"inet_addr", hle.ws2InetAddrStub},
		{"socket", hle.ws2SocketStub},
		{"WSAIoctl", hle.ws2IoctlStub},
		{"closesocket", hle.ws2CloseSocketStub},
	}
	for i, ex := range wsExports {
		nameOff := uint32(0x180 + i*0x10)
		binary.LittleEndian.PutUint32(ws[0x140+i*4:], ex.stub-Ws2Base)
		binary.LittleEndian.PutUint32(ws[0x160+i*4:], nameOff)
		binary.LittleEndian.PutUint16(ws[0x170+i*2:], uint16(i))
		copy(ws[nameOff:], ex.name+"\x00")
	}
	cpu := NewCPU(mem, hle.dispatch)
	hle.cpu = cpu

	// 导入表绑定到跨平台 HLE 存根
	impRVA := le32(img, e+24+96+8)
	if impRVA != 0 && impRVA < sizeImage {
		for d := impRVA; d+20 <= sizeImage; d += 20 {
			ilt, _, _, nameRva, iat := le32(imgSlice, int(d)), le32(imgSlice, int(d+4)), le32(imgSlice, int(d+8)), le32(imgSlice, int(d+12)), le32(imgSlice, int(d+16))
			if ilt == 0 && nameRva == 0 && iat == 0 {
				break
			}
			if iat >= sizeImage {
				break
			}
			dllName := cstrInSlice(imgSlice, nameRva, sizeImage)
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
				thunk := le32(imgSlice, int(tSlot))
				if thunk == 0 {
					break
				}
				var fnName string
				if thunk&0x80000000 != 0 {
					fnName = fmt.Sprintf("ord#%d", thunk&0xFFFF)
				} else if thunk+2 < sizeImage {
					fnName = cstrInSlice(imgSlice, thunk+2, sizeImage)
				}
				stub := hle.resolveImport(dllName, fnName)
				binary.LittleEndian.PutUint32(imgSlice[iSlot:iSlot+4], stub)
			}
		}
	}

	// AES 模板 K2 补丁
	if bytes.Contains(img, aesSboxSig) && dllCfgOffRVA < sizeImage && dllCfgL1RVA < sizeImage {
		l1 := imgSlice[dllCfgL1RVA]
		off1 := imgSlice[dllCfgOffRVA]
		if l1 > 0 {
			slot := dllPoolRVA + uint32(off1) + uint32(l1)
			if slot+16 <= sizeImage {
				copy(imgSlice[slot:slot+16], kh[:16])
			}
		}
	}

	// 运行态状态区重建
	ctxRVA := detectCtxRVA(img, codeRVA)
	if ctxRVA == 0 {
		ctxRVA = dllCtxRVA
	}
	vtblRVA := findSelfInitVtable(img, codeRVA)
	if ctxRVA >= 0x10 && ctxRVA+0xC8 <= sizeImage {
		desc := uint32(0)
		if vtblRVA > 8 {
			desc = vtblRVA - 8
		}
		for i := ctxRVA - 0x10; i < ctxRVA+0xC8; i++ {
			imgSlice[i] = 0
		}
		put := func(rva, v uint32) {
			if rva+4 <= sizeImage {
				binary.LittleEndian.PutUint32(imgSlice[rva:rva+4], v)
			}
		}
		put(ctxRVA-8, 1)
		put(ctxRVA-4, 0)
		put(ctxRVA+4, imageBase+desc)
		put(ctxRVA+8, 1)
		put(ctxRVA+0xC, 0x20)
		put(ctxRVA+0x10, mem.Alloc(0x100, true))
		put(ctxRVA+0x14, imageBase+desc)
		put(ctxRVA+0x18, 1)
		put(ctxRVA+0x1C, 0x20)
		put(ctxRVA+0x20, mem.Alloc(0x100, true))
		put(ctxRVA+0x24, 0xFFFFFFFF)
		put(ctxRVA+0x28, 0xFFFFFFFF)
		put(ctxRVA+0x2C, 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(imgSlice[ctxRVA:ctxRVA+4], FakeObjAddr)
	}

	_, textVA, _, textSize, _ := peTextInfo(img)
	textEnd := textVA + textSize
	PatchAntiTamperCallSite(imgSlice, codeRVA, textVA, textEnd)
	PatchAntiTamperCallSite(imgSlice, decRVA, textVA, textEnd)
	cpu.InitICache(imageBase+textVA, imageBase+textEnd)

	// 执行 DllMain(imageBase, DLL_PROCESS_ATTACH=1, 1) 完成 CRT + 全局变量初始化
	ep := le32(img, e+24+16)
	if ep != 0 && ep < sizeImage {
		_, err := cpu.Call(imageBase+ep, imageBase, 1, 1)
		if err != nil && !errors.Is(err, ErrExitThread) {
			return nil, fmt.Errorf("DllMain: %w", err)
		}
		cpu.Exited = false
	}

	return &Session{
		mem:     mem,
		hle:     hle,
		cpu:     cpu,
		codeVA:  imageBase + codeRVA,
		decVA:   imageBase + decRVA,
		imgBase: imageBase,
	}, nil
}

func (s *Session) call(fnVA uint32, input []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	inPtr := s.mem.Alloc(uint32(len(input))+16, true)
	if inPtr == 0 {
		return "", errors.New("x86emu: 输入缓冲分配失败")
	}
	defer s.mem.Free(inPtr)
	if err := s.mem.WriteBytes(inPtr, input); err != nil {
		return "", err
	}
	_ = s.mem.Write8(inPtr+uint32(len(input)), 0)

	limit := DefaultStepLimit + uint64(len(input))*100_000
	if limit > MaxStepLimit {
		limit = MaxStepLimit
	}
	s.cpu.StepLimit = limit
	s.cpu.Steps = 0
	s.cpu.Exited = false
	ret, err := s.cpu.Call(fnVA, inPtr)
	if err != nil && !errors.Is(err, ErrExitThread) {
		return "", err
	}
	if ret == 0 {
		return "", errors.New("x86emu: 算法函数返回空")
	}
	return s.mem.ReadCStr(ret, 1<<20), nil
}

func (s *Session) Code(plain []byte) (string, error) {
	return s.call(s.codeVA, plain)
}

func (s *Session) DeCode(hexStr string) (string, error) {
	return s.call(s.decVA, []byte(hexStr))
}

func (s *Session) Close() {}

// RunOnce 一次性初始化并执行 Code("enc") 或 DeCode("dec")
func RunOnce(img []byte, keyhex, mode string, input []byte) (string, error) {
	sess, err := NewSession(img, keyhex)
	if err != nil {
		return "", err
	}
	defer sess.Close()
	if mode == "dec" {
		return sess.DeCode(string(input))
	}
	return sess.Code(input)
}
