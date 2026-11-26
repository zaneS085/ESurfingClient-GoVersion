package x86emu

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ulikunitz/xz/lzma"
)

func TestALUBasicAndShifts(t *testing.T) {
	res, ef := aluAdd(0x7FFFFFFF, 1, 0, 0, 32)
	if res != 0x80000000 || ef&flagOF == 0 || ef&flagSF == 0 || ef&flagCF != 0 {
		t.Fatalf("aluAdd overflow mismatch: res=0x%x ef=0x%x", res, ef)
	}
	res, ef = aluSub(5, 10, 0, 0, 32)
	if res != 0xFFFFFFFB || ef&flagCF == 0 || ef&flagSF == 0 {
		t.Fatalf("aluSub borrow mismatch: res=0x%x ef=0x%x", res, ef)
	}
	res, ef = aluShift(0, 0x80000001, 1, 0, 32) // ROL 1
	if res != 0x00000003 || ef&flagCF == 0 || ef&flagOF == 0 {
		t.Fatalf("ROL mismatch: res=0x%x ef=0x%x", res, ef)
	}
	res, ef = aluShift(7, 0x80000001, 1, 0, 32) // SAR 1
	if res != 0xC0000000 || ef&flagCF == 0 || ef&flagSF == 0 {
		t.Fatalf("SAR mismatch: res=0x%x ef=0x%x", res, ef)
	}
}

func TestCPUAndHLEFormatting(t *testing.T) {
	mem := NewMem(0x10000000, 0x4000)
	hle := newHLEEnv(mem)
	cpu := NewCPU(mem, hle.dispatch)
	hle.cpu = cpu

	// 编写一个小 x86-32 程序计算 sum(1..n) 并返回
	// int sum(int n) { int s=0; for(int i=1;i<=n;i++) s+=i; return s; }
	// [esp+4] = n
	code := []byte{
		0x8B, 0x4C, 0x24, 0x04, // mov ecx, [esp+4]
		0x31, 0xC0, // xor eax, eax
		0x85, 0xC9, // test ecx, ecx
		0x7E, 0x06, // jle done
		// loop:
		0x01, 0xC8, // add eax, ecx
		0x49,       // dec ecx
		0x75, 0xFB, // jne loop
		// done:
		0xC3, // ret
	}
	_ = mem.WriteBytes(0x10001000, code)
	got, err := cpu.Call(0x10001000, 10)
	if err != nil || got != 55 {
		t.Fatalf("cpu sum(10) = (%d, %v), want 55", got, err)
	}

	// 验证 HLE __stdio_common_vsprintf (64位 options 占 2 栈槽) + strtol + ord5/ord9
	buf := mem.Alloc(128, true)
	fmtAddr := mem.AllocCStr("id=%s n=%04X")
	strArg := mem.AllocCStr("demo")
	va := mem.Alloc(16, true)
	_ = mem.Write32(va, strArg)
	_ = mem.Write32(va+4, 0xAB)

	vsprintfStub := hle.resolveImport("api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vsprintf")
	n, err := cpu.Call(vsprintfStub, 0, 0, buf, 128, fmtAddr, 0, va)
	if err != nil || mem.ReadCStr(buf, 128) != "id=demo n=00AB" || n != 14 {
		t.Fatalf("vsprintf = (%d, %q, %v)", n, mem.ReadCStr(buf, 128), err)
	}

	val, cons := cStrtol("  -0x1f!", 0)
	if val != -31 || cons != 7 {
		t.Fatalf("strtol = (%d, %d), want (-31, 7)", val, cons)
	}
}

func unpackSamplePEForTest(raw []byte) ([]byte, string) {
	if len(raw) >= 2 && raw[0] == 'M' && raw[1] == 'Z' {
		return raw, "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	}
	i := bytes.IndexByte(raw, ']')
	d := bytes.IndexByte(raw, '$')
	if i < 0 || d < 4 || len(raw) < i+13 || !bytes.Equal(raw[:3], []byte("001")) {
		return nil, ""
	}
	keyhex := string(raw[4:d])
	blob := raw[i:]
	if blob[0] != 0x5D {
		return nil, ""
	}
	keyA := []uint32{0x464B697C, 0x463B6D4D, 0x36496A5A, 0x4774496F}
	keyB := []uint32{0x356D766D, 0x52783633, 0x2D4A4D38, 0x39384335}
	xteaDec := func(v0, v1 uint32, k []uint32) (uint32, uint32) {
		const delta uint32 = 0x9E3779B9
		var rounds uint32 = 32
		sum := rounds * delta
		for r := 0; r < 32; r++ {
			v1 -= ((v0 << 4) ^ (v0 >> 5)) + (v0 ^ sum) + k[(sum>>11)&3]
			sum -= delta
			v0 -= ((v1 << 4) ^ (v1 >> 5)) + (v1 ^ sum) + k[sum&3]
		}
		return v0, v1
	}
	out := append([]byte{}, blob[9:]...)
	for off := 0; off+8 <= len(out); off += 8 {
		v0 := binary.LittleEndian.Uint32(out[off:])
		v1 := binary.LittleEndian.Uint32(out[off+4:])
		v0, v1 = xteaDec(v0, v1, keyA)
		v0, v1 = xteaDec(v0, v1, keyB)
		binary.LittleEndian.PutUint32(out[off:], v0)
		binary.LittleEndian.PutUint32(out[off+4:], v1)
	}
	dstSize := uint64(binary.LittleEndian.Uint32(blob[5:9])) & 0xFFFFFFF
	var hdr bytes.Buffer
	hdr.Write(blob[:5])
	_ = binary.Write(&hdr, binary.LittleEndian, dstSize)
	hdr.Write(out)
	r, err := lzma.NewReader(&hdr)
	if err != nil {
		return nil, ""
	}
	pe := make([]byte, dstSize)
	if _, err := io.ReadFull(r, pe); err != nil {
		return nil, ""
	}
	if len(pe) < 2 || pe[0] != 'M' || pe[1] != 'Z' {
		return nil, ""
	}
	return pe, keyhex
}

// TestRealLocalDLLSamplesRoundTrip 在本地真实下发的所有服务端 DLL 样本上端到端验证 x86emu (Code → DeCode)
func TestRealLocalDLLSamplesRoundTrip(t *testing.T) {
	sampleDir := strings.TrimSpace(os.Getenv("GDPORTAL_SAMPLE_DIR"))
	if sampleDir == "" {
		t.Skip("未设置 GDPORTAL_SAMPLE_DIR，跳过本地 DLL 样本端到端测试")
	}
	entries, err := os.ReadDir(sampleDir)
	if err != nil {
		t.Skip("本地样本目录不存在，跳过")
	}
	xmlIn := []byte(`<?xml version="1.0" encoding="utf-8"?><request>
<ostag>Windows 11(26200),64 bit </ostag>
<local-time>0000000&lt;;</local-time>
<gwip>10.20.30.254</gwip>
<mac>02-00-5E-10-20-30</mac>
<ipv6></ipv6>
<ipv4>10.20.30.40</ipv4>
<client-id>11111111-2222-3333-4444-555555555555</client-id>
<user-agent>CCTP/WinSVR5/1068</user-agent>
<host-name>TEST-HOST</host-name>
<userid>13800138000</userid>
</request>`)

	tested := 0
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".bin") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(sampleDir, ent.Name()))
		if err != nil {
			continue
		}
		pe, keyhex := unpackSamplePEForTest(raw)
		if pe == nil {
			continue
		}
		if _, e1 := FindFuncRVA(pe, CodePat); e1 != nil {
			continue
		}
		if _, e2 := FindFuncRVA(pe, DecPat); e2 != nil {
			continue
		}

		t.Run(ent.Name(), func(t *testing.T) {
			sess, err := NewSession(pe, keyhex)
			if err != nil {
				t.Fatalf("NewSession(%s): %v", ent.Name(), err)
			}
			defer sess.Close()

			enc, err := sess.Code(xmlIn)
			if err != nil || len(enc) < 64 {
				t.Fatalf("Code(%s): len=%d err=%v", ent.Name(), len(enc), err)
			}
			dec, err := sess.DeCode(enc)
			if err != nil {
				t.Fatalf("DeCode(%s): err=%v (enc[:48]=%s)", ent.Name(), err, enc[:48])
			}
			for _, tok := range []string{
				`<user-agent>CCTP/WinSVR5/1068</user-agent>`,
				`<host-name>TEST-HOST</host-name>`,
				`<client-id>11111111-2222-3333-4444-555555555555</client-id>`,
				`<ipv4>10.20.30.40</ipv4>`,
			} {
				if strings.Contains(string(xmlIn), tok) && !strings.Contains(dec, tok) {
					t.Fatalf("roundtrip lost %s in %s:\n%s", tok, ent.Name(), dec)
				}
			}
			if strings.Contains(dec, `<local-time>000000000</local-time>`) {
				t.Fatalf("RDTSC local-time stayed all-zero in %s:\n%s", ent.Name(), dec)
			}
			// 验证极短 4B 自检输入 <t/> 在所有真实模板均可正常加解密往返
			shortEnc, err := sess.Code([]byte("<t/>"))
			if err != nil || len(shortEnc) == 0 {
				t.Fatalf("Code(<t/>) failed in %s: %v", ent.Name(), err)
			}
			shortDec, err := sess.DeCode(shortEnc)
			if err != nil || (!strings.Contains(shortDec, "<t></t>") && !strings.Contains(shortDec, "<t/>")) {
				t.Fatalf("DeCode(<t/>) failed in %s: dec=%q err=%v", ent.Name(), shortDec, err)
			}
			t.Logf("%s: Code=%d hexB, steps OK -> DeCode=%dB", ent.Name(), len(enc), len(dec))
		})
		tested++
	}
	if tested == 0 {
		t.Skip("样本目录中未找到有效算法 PE")
	}
	t.Logf("Total real DLL samples verified cleanly in pure-Go x86emu: %d", tested)
}

// TestLargeXMLBitwise3DESStepLimit 验证大体积 XML (~2.5KB，如 auth.cgi 响应) 在逐位 3DES 模板下的步数上限扩展
func TestLargeXMLBitwise3DESStepLimit(t *testing.T) {
	sampleDir := strings.TrimSpace(os.Getenv("GDPORTAL_SAMPLE_DIR"))
	if sampleDir == "" {
		t.Skip("未设置 GDPORTAL_SAMPLE_DIR，跳过本地样本步数上限测试")
	}
	pePath := filepath.Join(sampleDir, "gen_32C8C121.bin")
	pe, err := os.ReadFile(pePath)
	if err != nil {
		t.Skip("本地 gen_32C8C121.bin 样本不存在，跳过")
	}
	sess, err := NewSession(pe, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	largeXML := []byte(`<?xml version="1.0" encoding="utf-8"?><response>` +
		`<keep-url>http://203.0.113.142:7001/keep.cgi</keep-url>` +
		`<term-url>http://203.0.113.141:7001/term.cgi</term-url>` +
		`<ipv4>10.20.30.40</ipv4>` +
		`<user-agent>CCTP/WinSVR5/1068</user-agent>` +
		`<notice>` + strings.Repeat("GDPORTAL_AUTH_RESPONSE_PADDING_BLOCK_0123456789ABCDEF_", 40) + `</notice>` +
		`</response>`)

	t0 := time.Now()
	enc, err := sess.Code(largeXML)
	if err != nil {
		t.Fatalf("Code(%dB): %v", len(largeXML), err)
	}
	codeSteps := sess.cpu.Steps
	codeDur := time.Since(t0)

	t1 := time.Now()
	dec, err := sess.DeCode(enc)
	if err != nil {
		t.Fatalf("DeCode(%d hexB): %v", len(enc), err)
	}
	decSteps := sess.cpu.Steps
	decDur := time.Since(t1)

	for _, tok := range []string{
		`<keep-url>http://203.0.113.142:7001/keep.cgi</keep-url>`,
		`<term-url>http://203.0.113.141:7001/term.cgi</term-url>`,
		`<ipv4>10.20.30.40</ipv4>`,
		`<user-agent>CCTP/WinSVR5/1068</user-agent>`,
	} {
		if !strings.Contains(dec, tok) {
			t.Fatalf("roundtrip lost %s:\n%s", tok, dec)
		}
	}
	t.Logf("2.5KB XML bitwise-3DES: Code=%d steps (%v) | DeCode=%d steps (%v)", codeSteps, codeDur, decSteps, decDur)
}
