package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"gdportal-lite/x86emu"
	"os"
)

var dllVerbose = os.Getenv("DLL_DEBUG") == "1"

func isDllVerbose() bool {
	return dllVerbose || isDebugMode()
}

func dllLogf(format string, args ...any) {
	if isDllVerbose() {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

func patchAntiTamperCallSite(mem []byte, fnRVA, textVA, textEnd uint32) int {
	return x86emu.PatchAntiTamperCallSite(mem, fnRVA, textVA, textEnd)
}

const patAny = 256

var dllCodePat = []int{0x55, 0x8b, 0xec, 0x83, 0xec, patAny, 0x53, 0x56, 0x57, 0x74, 0x14, 0x75, 0x12}
var dllDecPat = []int{0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0x83, 0xec, patAny, 0x53, 0x56, 0x57}

func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func le16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func bytesEq2(b []byte, s string) bool {
	return len(b) >= len(s) && string(b[:len(s)]) == s
}

func findFuncRVA(img []byte, pat []int) (uint32, error) {
	if len(pat) == len(dllCodePat) && pat[3] == 0x83 {
		return x86emu.FindFuncRVA(img, x86emu.CodePat)
	}
	return x86emu.FindFuncRVA(img, x86emu.DecPat)
}

// emuCipher 通过纯 Go x86-32 用户态模拟执行器 (x86emu) 运行服务端下发 DLL，
// 零 CGO、零 VirtualAlloc(RWX)、零字典，原生兼容 Windows/Linux/macOS 全架构。
type emuCipher struct {
	sess *x86emu.Session
}

func (e *emuCipher) Encrypt(p []byte) (string, error) {
	if e == nil || e.sess == nil {
		return "", errors.New("x86emu 会话已关闭")
	}
	return e.sess.Code(p)
}

func (e *emuCipher) Decrypt(h string) ([]byte, error) {
	if e == nil || e.sess == nil {
		return nil, errors.New("x86emu 会话已关闭")
	}
	s, err := e.sess.DeCode(h)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func (e *emuCipher) Close() {
	if e != nil && e.sess != nil {
		e.sess.Close()
		e.sess = nil
	}
}

func newDynamicDLLCipher(pe []byte, keyhex string) (Cipher, string, error) {
	if preferNativeDLLEngine() {
		ci, err := newNativeDLLCipher(pe, keyhex)
		if err != nil {
			return nil, "", err
		}
		return ci, "32位原生 DLL 引擎", nil
	}
	sess, err := x86emu.NewSession(pe, keyhex)
	if err != nil {
		return nil, "", err
	}
	return &emuCipher{sess: sess}, "纯Go x86emu引擎(跨平台)", nil
}
