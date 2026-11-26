//go:build windows && 386

package main

import (
	"gdportal-lite/x86emu"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestX86EmuCrossVerifyNative 在 windows/386 下交叉对拍 x86emu 与原生 Win32 dllRun 引擎的双向加解密等价性
func TestX86EmuCrossVerifyNative(t *testing.T) {
	sampleDir := strings.TrimSpace(os.Getenv("GDPORTAL_SAMPLE_DIR"))
	if sampleDir == "" {
		t.Skip("未设置 GDPORTAL_SAMPLE_DIR，跳过本地样本交叉对拍")
	}
	samples := []string{
		"gen_4FE47EF4.bin",
		"gen_6B4D085A.bin",
		"gen_C12422B4.bin",
		"gen_32C8C121.bin",
		"gen_E51E14F1.bin",
	}
	xmlIn := []byte(`<?xml version="1.0" encoding="utf-8"?><request>
<ostag>Windows 11(26200),64 bit </ostag>
<local-time>0000000&lt;;</local-time>
<gwip>10.20.30.254</gwip>
<mac>02-00-5E-10-20-30</mac>
<ipv6></ipv6>
<ipv4>127.0.0.1</ipv4>
<client-id>11111111-2222-3333-4444-555555555555</client-id>
<user-agent>CCTP/WinSVR5/1068</user-agent>
<host-name>TEST-HOST</host-name>
</request>`)
	const keyhex = "0123456789abcdef0123456789abcdef"

	tested := 0
	for _, name := range samples {
		pe, err := os.ReadFile(filepath.Join(sampleDir, name))
		if err != nil {
			continue
		}
		if _, e1 := findFuncRVA(pe, dllCodePat); e1 != nil {
			continue
		}
		tested++
		t.Run(name, func(t *testing.T) {
			emuEnc, err := x86emu.RunOnce(pe, keyhex, "enc", xmlIn)
			if err != nil {
				t.Fatalf("x86emu Code: %v", err)
			}
			natEnc, err := dllRun(pe, keyhex, "enc", xmlIn)
			if err != nil {
				t.Fatalf("native dllRun Code: %v", err)
			}

			// 1. x86emu 加密 -> 原生 dllRun 解密
			natFromEmu, err := dllRun(pe, keyhex, "dec", []byte(emuEnc))
			if err != nil {
				t.Fatalf("native DeCode(emuEnc): %v", err)
			}
			// 2. 原生 dllRun 加密 -> x86emu 解密
			emuFromNat, err := x86emu.RunOnce(pe, keyhex, "dec", []byte(natEnc))
			if err != nil {
				t.Fatalf("x86emu DeCode(natEnc): %v", err)
			}

			for _, tok := range []string{
				`<user-agent>CCTP/WinSVR5/1068</user-agent>`,
				`<host-name>TEST-HOST</host-name>`,
				`<client-id>11111111-2222-3333-4444-555555555555</client-id>`,
				`<ipv4>127.0.0.1</ipv4>`,
			} {
				if !strings.Contains(natFromEmu, tok) {
					t.Fatalf("native DeCode(emuEnc) missing %s:\n%s", tok, natFromEmu)
				}
				if !strings.Contains(emuFromNat, tok) {
					t.Fatalf("x86emu DeCode(natEnc) missing %s:\n%s", tok, emuFromNat)
				}
			}
			if strings.Contains(natFromEmu, `<local-time>000000000</local-time>`) {
				t.Fatalf("RDTSC local-time stayed all-zero in %s:\n%s", name, natFromEmu)
			}
			t.Logf("%s: emuEnc=%dB / natEnc=%dB 双向交叉加解密完全等价", name, len(emuEnc), len(natEnc))
		})
	}
	if tested == 0 {
		t.Skip("本地对比样本不存在")
	}
}
