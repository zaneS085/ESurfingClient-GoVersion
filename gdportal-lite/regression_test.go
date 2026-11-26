package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// 1. 全 9 个静态算法: 多种长度往返、不篡改入参、单层大写 hex、非法/截断密文不 panic
func TestAllStaticCiphersRoundTripAndSafety(t *testing.T) {
	algos := []string{
		AlgoAesEcb, AlgoAesCbc, AlgoXTea, AlgoXTeaIv,
		AlgoSm4Cbc, AlgoSm4Ecb, AlgoZUC, AlgoDesCbc, AlgoDesEcb,
	}
	lengths := []int{0, 1, 4, 7, 8, 15, 16, 17, 363}

	for _, id := range algos {
		ci, err := newCipher(id)
		if err != nil {
			t.Fatalf("newCipher(%s): %v", id, err)
		}
		for _, ln := range lengths {
			orig := make([]byte, ln)
			for i := range orig {
				orig[i] = byte('A' + (i % 26))
			}
			// 预留额外容量以检测 append 是否篡改调用方底层数组
			backing := make([]byte, ln, ln+32)
			copy(backing, orig)
			for i := ln; i < cap(backing); i++ {
				backing[:cap(backing)][i] = 0xAA
			}
			input := backing[:ln]

			enc, err := ci.Encrypt(input)
			if err != nil {
				t.Fatalf("%s Encrypt(len=%d): %v", id, ln, err)
			}
			if !bytes.Equal(input, orig) {
				t.Fatalf("%s Encrypt 原地篡改了输入切片 (len=%d)", id, ln)
			}
			if backing[:cap(backing)][ln] != 0xAA {
				t.Fatalf("%s Encrypt 越界写入了输入切片的备用容量 (len=%d)", id, ln)
			}
			// 验证是单层大写 hex (偶数字符且不含非 hex 字符)
			if (ln > 0 && len(enc) == 0) || len(enc)%2 != 0 || enc != strings.ToUpper(enc) {
				t.Fatalf("%s Encrypt 输出非标准大写 hex (len=%d): %q", id, ln, enc)
			}
			// 若是双层 hex 会全部落在 '30'..'46'，单层正常密文对 363B 必然出现 > '46' 字节
			if ln == 363 {
				hasHighHex := false
				for i := 0; i < len(enc); i++ {
					if enc[i] > 'F' || (enc[i] > '9' && enc[i] < 'A') {
						t.Fatalf("%s 非法 hex 字符: %c", id, enc[i])
					}
					if enc[i] >= '8' && enc[i] <= 'F' {
						hasHighHex = true
					}
				}
				if !hasHighHex {
					t.Fatalf("%s 疑似双重 hex 编码: %.40s", id, enc)
				}
			}

			dec, err := ci.Decrypt(enc)
			if err != nil {
				t.Fatalf("%s Decrypt(len=%d): %v", id, ln, err)
			}
			if !bytes.Equal(dec, orig) {
				t.Fatalf("%s 往返不一致 (len=%d): got=%x want=%x", id, ln, dec, orig)
			}
		}

		// 非法/非对齐/空密文不能 panic
		for _, bad := range []string{"", "ZZ", "0", "AABB", "00112233445566778899AABBCCDDEEFF"} {
			_, _ = ci.Decrypt(bad)
		}
	}
}

// 2. dynAesCipher: 结构体字面量初始化 + 并发调用 block 缓存安全
func TestDynAesCipherConcurrentLiteral(t *testing.T) {
	c := &dynAesCipher{
		key1: []byte("0123456789abcdef0123456789abcdef"),
		iv:   []byte("fedcba9876543210"),
	}
	plain := []byte("<?xml version=\"1.0\"?><request><user>test</user></request>")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enc, err := c.Encrypt(plain)
			if err != nil {
				errs <- err
				return
			}
			dec, err := c.Decrypt(enc)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(dec, plain) {
				errs <- errors.New("dynAesCipher concurrent mismatch")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// 3. DecodeAlgoID 与 decodeStaticTicket 一致性 + '$' 后备格式 + 畸形输入
func TestDecodeAlgoIDConsistency(t *testing.T) {
	key := "0123456789abcdef"
	// 标准 len-prefixed 格式: [3B][1B keyLen][key][0x24=36][36B UUID]
	std := make([]byte, 0, 4+len(key)+1+36)
	std = append(std, 0x01, 0x02, 0x03, byte(len(key)))
	std = append(std, key...)
	std = append(std, 36)
	std = append(std, AlgoSm4Cbc...)

	id1, k1, err := DecodeAlgoID(std)
	if err != nil || id1 != AlgoSm4Cbc || k1 != key {
		t.Fatalf("DecodeAlgoID(std) = (%q, %q, %v)", id1, k1, err)
	}
	ci, id2, err := decodeStaticTicket(std)
	if err != nil || id2 != AlgoSm4Cbc || ci == nil {
		t.Fatalf("decodeStaticTicket(std) = (%v, %q, %v)", ci, id2, err)
	}

	// '$' 分隔后备格式: [3B][1B keyLen][key]['$'][1B 36][36B UUID]
	alt := make([]byte, 0, 4+len(key)+2+36)
	alt = append(alt, 0x01, 0x02, 0x03, byte(len(key)))
	alt = append(alt, key...)
	alt = append(alt, '$', 36)
	alt = append(alt, AlgoZUC...)
	id3, k3, err := DecodeAlgoID(alt)
	if err != nil || id3 != AlgoZUC || k3 != key {
		t.Fatalf("DecodeAlgoID(alt) = (%q, %q, %v)", id3, k3, err)
	}

	// 畸形输入不应 panic
	for _, bad := range [][]byte{nil, {}, {0, 0, 0, 200}, []byte("001$short")} {
		if _, _, err := DecodeAlgoID(bad); err == nil {
			t.Fatalf("expected error for bad input %x", bad)
		}
	}
}

type oneBurstEOFConn struct {
	net.Conn
	data []byte
	read bool
}

func (c *oneBurstEOFConn) Read(p []byte) (int, error) {
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	n := copy(p, c.data)
	return n, io.EOF
}

func (c *oneBurstEOFConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *oneBurstEOFConn) Close() error                       { return nil }
func (c *oneBurstEOFConn) LocalAddr() net.Addr                { return nil }
func (c *oneBurstEOFConn) RemoteAddr() net.Addr               { return nil }
func (c *oneBurstEOFConn) SetDeadline(t time.Time) error      { return nil }
func (c *oneBurstEOFConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *oneBurstEOFConn) SetWriteDeadline(t time.Time) error { return nil }

// 4. HTTP / readHTTPMessage / dechunk / chunkedComplete 边界矩阵
func TestHTTPMessageAndChunkedEdgeCases(t *testing.T) {
	// 4a. 多 chunk + chunk-ext + 尾部空格 + 在 0\r\n 与末尾 \r\n 之间分片
	rawResp := "HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Connection: close\r\n\r\n" +
		"5;ext=1\r\nhello\r\n" +
		"6 \r\n world\r\n" +
		"0\r\n\r\n"
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		b := []byte(rawResp)
		// 故意切在末尾 \r\n 之前
		_, _ = c2.Write(b[:len(b)-2])
		time.Sleep(15 * time.Millisecond)
		_, _ = c2.Write(b[len(b)-2:])
	}()
	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))
	_, chunkedBody, err := readHTTPMessage(c1)
	_ = c1.Close()
	if err != nil {
		t.Fatalf("chunked split readHTTPMessage: %v", err)
	}
	if got := string(dechunk(chunkedBody)); got != "hello world" {
		t.Fatalf("dechunk = %q, want %q", got, "hello world")
	}

	// 4b. 负数/超大(>2GB) chunk-size 在 32 位下绝不能 panic
	for _, badChunk := range [][]byte{
		[]byte("-1\r\nabc\r\n0\r\n\r\n"),
		[]byte("80000000\r\nabc\r\n0\r\n\r\n"),
		[]byte("100000000\r\nabc\r\n0\r\n\r\n"),
	} {
		_ = chunkedComplete(badChunk)
		_ = dechunk(badChunk)
	}

	// 4c. 无 Content-Length 且非 chunked 的 Connection: close 应读到 EOF，不能截断成空
	c1, c2 = net.Pipe()
	go func() {
		_, _ = c2.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npart1-"))
		time.Sleep(10 * time.Millisecond)
		_, _ = c2.Write([]byte("part2"))
		_ = c2.Close()
	}()
	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))
	_, eofBody, err := readHTTPMessage(c1)
	_ = c1.Close()
	if err != nil {
		t.Fatalf("EOF body readHTTPMessage: %v", err)
	}
	if string(eofBody) != "part1-part2" {
		t.Fatalf("EOF body = %q, want %q", string(eofBody), "part1-part2")
	}

	// 4d. 单次 Read 返回 (n > 0, io.EOF) 必须成功
	singleBurst := &oneBurstEOFConn{
		data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
	}
	_, bbody, err := readHTTPMessage(singleBurst)
	if err != nil || string(bbody) != "hello" {
		t.Fatalf("oneBurstEOFConn: body=%q err=%v", string(bbody), err)
	}

	// 4e. Content-Length 未满提前 EOF 必须报错
	c1, c2 = net.Pipe()
	go func() {
		_, _ = c2.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345"))
		_ = c2.Close()
	}()
	if _, _, err := readHTTPMessage(c1); err == nil {
		t.Fatal("truncated Content-Length should return error")
	}
	_ = c1.Close()

	// 4f. chunked 未到 0\r\n 提前 EOF 必须报错
	c1, c2 = net.Pipe()
	go func() {
		_, _ = c2.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"))
		_ = c2.Close()
	}()
	if _, _, err := readHTTPMessage(c1); err == nil {
		t.Fatal("truncated chunked should return error")
	}
	_ = c1.Close()
}

// 5. extractIndexParams / extractTag / xmlEscape / solvePayload 边界检查
func TestParsersAndSolvePayloadBounds(t *testing.T) {
	cl := &Client{}
	if err := cl.extractIndexParams("http://203.0.113.212:7001/index.cgi?wlanacip=1.2.3.4&foo=bar&wlanuserip=10.1.2.3"); err != nil {
		t.Fatalf("extractIndexParams reversed: %v", err)
	}
	if cl.userIP != "10.1.2.3" || cl.acIP != "1.2.3.4" {
		t.Fatalf("got userIP=%q acIP=%q", cl.userIP, cl.acIP)
	}

	if got := extractTag("<ticket><![CDATA[abc&123]]></ticket>", "ticket"); got != "abc&123" {
		t.Fatalf("extractTag CDATA = %q", got)
	}
	if got := extractTag("  <keep-url>http://a/keep.cgi</keep-url> ", "keep-url"); got != "http://a/keep.cgi" {
		t.Fatalf("extractTag plain = %q", got)
	}
	if got := xmlEscape(`a&b<c>d"e`); got != "a&amp;b&lt;c&gt;d&#34;e" {
		t.Fatalf("xmlEscape = %q", got)
	}

	// solvePayload: dollar==3 ("001$...") 与超大 dstSize 不能 panic
	pDollar3 := append([]byte("001$"+AlgoAesCbc+"]"), make([]byte, 20)...)
	for len(pDollar3) < 80 {
		pDollar3 = append(pDollar3, '0')
	}
	if _, _, _, _, _, _, err := solvePayload(pDollar3); err == nil {
		t.Fatal("expected error for dollar==3 payload")
	}

	huge := make([]byte, 120)
	copy(huge, "001@"+strings.Repeat("00", 16)+"$"+AlgoAesCbc+"]")
	idx := bytes.IndexByte(huge, ']')
	huge[idx] = 0x5D
	binary.LittleEndian.PutUint32(huge[idx+5:idx+9], 0x0FFFFFFF)
	if _, _, _, _, _, _, err := solvePayload(huge); err == nil {
		t.Fatal("expected error for oversized dstSize")
	}
}

// 6. patchAntiTamperCallSite 覆盖 je/jne rel8/rel32 四种分支形态
func TestPatchAntiTamperCallSite(t *testing.T) {
	makeImg := func(branch []byte) []byte {
		mem := make([]byte, 0x2000)
		fnRVA := 0x1000
		tgtRVA := 0x1200
		// call tgtRVA at fnRVA+0: E8 rel32
		mem[fnRVA] = 0xE8
		rel := int32(tgtRVA - (fnRVA + 5))
		binary.LittleEndian.PutUint32(mem[fnRVA+1:fnRVA+5], uint32(rel))
		// test eax, eax (85 C0) + branch
		mem[fnRVA+5], mem[fnRVA+6] = 0x85, 0xC0
		copy(mem[fnRVA+7:], branch)
		// 目标含 mov eax, fs:[0x30] (64 A1 30 00 00 00)
		copy(mem[tgtRVA:], []byte{0x64, 0xA1, 0x30, 0x00, 0x00, 0x00})
		return mem
	}

	// je rel8 (74 10) -> B0 01 90 90
	m1 := makeImg([]byte{0x74, 0x10})
	if n := patchAntiTamperCallSite(m1, 0x1000, 0x1000, 0x1800); n != 1 {
		t.Fatalf("je rel8 patched=%d", n)
	}
	if !bytes.Equal(m1[0x1005:0x1009], []byte{0xB0, 0x01, 0x90, 0x90}) {
		t.Fatalf("je rel8 bytes=%x", m1[0x1005:0x1009])
	}

	// jne rel8 (75 10) -> B0 01 EB 10
	m2 := makeImg([]byte{0x75, 0x10})
	if n := patchAntiTamperCallSite(m2, 0x1000, 0x1000, 0x1800); n != 1 {
		t.Fatalf("jne rel8 patched=%d", n)
	}
	if !bytes.Equal(m2[0x1005:0x1009], []byte{0xB0, 0x01, 0xEB, 0x10}) {
		t.Fatalf("jne rel8 bytes=%x", m2[0x1005:0x1009])
	}

	// je rel32 (0F 84 44 33 22 11) -> B0 01 90 90 90 90 90 90
	m3 := makeImg([]byte{0x0F, 0x84, 0x44, 0x33, 0x22, 0x11})
	if n := patchAntiTamperCallSite(m3, 0x1000, 0x1000, 0x1800); n != 1 {
		t.Fatalf("je rel32 patched=%d", n)
	}
	if !bytes.Equal(m3[0x1005:0x100D], []byte{0xB0, 0x01, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}) {
		t.Fatalf("je rel32 bytes=%x", m3[0x1005:0x100D])
	}

	// jne rel32 (0F 85 44 33 22 11) -> B0 01 90 E9 44 33 22 11
	m4 := makeImg([]byte{0x0F, 0x85, 0x44, 0x33, 0x22, 0x11})
	if n := patchAntiTamperCallSite(m4, 0x1000, 0x1000, 0x1800); n != 1 {
		t.Fatalf("jne rel32 patched=%d", n)
	}
	if !bytes.Equal(m4[0x1005:0x100D], []byte{0xB0, 0x01, 0x90, 0xE9, 0x44, 0x33, 0x22, 0x11}) {
		t.Fatalf("jne rel32 bytes=%x", m4[0x1005:0x100D])
	}
}

// 7. windowsBuild 跨平台协议格式校验
func TestWindowsBuildTagFormat(t *testing.T) {
	wb := windowsBuild()
	if !strings.HasPrefix(wb, "Windows ") || !strings.HasSuffix(wb, ",64 bit ") {
		t.Fatalf("unexpected windowsBuild: %q", wb)
	}
}

// 9. candidateTicketURLs 优先级: 实时下发节点 (portalPage / ticketURL) 必须优先于过期 portal_cache.txt 与静态回退表 knownPortals
func TestCandidateTicketURLsPriority(t *testing.T) {
	origCache, cacheErr := os.ReadFile(portalCacheFile)
	if cacheErr == nil {
		defer func() { _ = os.WriteFile(portalCacheFile, origCache, 0644) }()
	} else {
		defer func() { _ = os.Remove(portalCacheFile) }()
	}
	if err := os.WriteFile(portalCacheFile, []byte("http://203.0.113.141:7001\n"), 0644); err != nil {
		t.Fatalf("write stale cache: %v", err)
	}

	cl := &Client{
		school:     "888",
		userIP:     "10.20.30.40",
		acIP:       "198.51.100.245",
		portalPage: "http://203.0.113.212:7001/portal.html",
		ticketURL:  "http://203.0.113.212:7001/ticket.cgi?wlanuserip=10.20.30.40&wlanacip=198.51.100.245",
	}
	urls := cl.candidateTicketURLs()
	if len(urls) < 2 {
		t.Fatalf("candidateTicketURLs too short: %v", urls)
	}
	if !strings.HasPrefix(urls[0], "http://203.0.113.212:7001/ticket.cgi") {
		t.Fatalf("expected live portalPage first (ahead of stale cache), got: %v", urls)
	}
	cacheIdx := -1
	for i, u := range urls {
		if strings.HasPrefix(u, "http://203.0.113.141:7001/ticket.cgi") {
			cacheIdx = i
			break
		}
	}
	if cacheIdx <= 0 {
		t.Fatalf("expected stale portal_cache.txt as fallback after live URL, got: %v", urls)
	}

	// portalPage 为空时，实时 ticketURL 同样必须排在过期 portal_cache.txt 之前
	cl2 := &Client{
		school:    "888",
		userIP:    "10.20.30.40",
		acIP:      "198.51.100.245",
		ticketURL: "http://10.0.0.1:7001/ticket.cgi?wlanuserip=10.20.30.40&wlanacip=198.51.100.245",
	}
	urls2 := cl2.candidateTicketURLs()
	if len(urls2) < 2 || !strings.HasPrefix(urls2[0], "http://10.0.0.1:7001/ticket.cgi") {
		t.Fatalf("expected live ticketURL first when portalPage empty, got: %v", urls2)
	}
	if !strings.HasPrefix(urls2[1], "http://203.0.113.141:7001/ticket.cgi") {
		t.Fatalf("expected stale cache second after live ticketURL, got: %v", urls2)
	}
}

// 10. 网关 502/503/504 瞬时故障自动快速重试，业务 Error-Code 不误重试
func TestTransientGatewayRetry(t *testing.T) {
	origDelays := append([]time.Duration(nil), gatewayRetryDelays...)
	gatewayRetryDelays = []time.Duration{
		5 * time.Millisecond,
		5 * time.Millisecond,
		5 * time.Millisecond,
		5 * time.Millisecond,
		5 * time.Millisecond,
	}
	defer func() { gatewayRetryDelays = origDelays }()

	ci := &dynAesCipher{
		key1: []byte("0123456789abcdef0123456789abcdef"),
		iv:   []byte("fedcba9876543210"),
	}
	const wantRespXML = `<?xml version="1.0"?><response><interval>300</interval></response>`
	encResp, err := ci.Encrypt([]byte(wantRespXML))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 10a. postXML: 502 -> 502 -> 200 自动恢复
	var hits502Recover int32
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits502Recover, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><html><head><meta name="author" content="Limnk" /></head></html>`)
			return
		}
		w.Header().Set("Error-Code", "0")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, encResp)
	}))
	defer srv1.Close()

	cl := &Client{cipher: ci, algoID: AlgoAesCbc, clientID: "cid-1", school: "888", domain: "campusdemo", area: "0759"}
	gotXML, err := cl.postXML(srv1.URL+"/keep.cgi", "<request><hello>1</hello></request>")
	if err != nil {
		t.Fatalf("postXML 502 recovery failed: %v", err)
	}
	if gotXML != wantRespXML {
		t.Fatalf("postXML = %q, want %q", gotXML, wantRespXML)
	}
	if atomic.LoadInt32(&hits502Recover) != 3 {
		t.Fatalf("hits502Recover = %d, want 3", hits502Recover)
	}

	// 10b. postXML: 持续 502 在 1+5=6 次后报错并附带 HTTP=502
	var hitsAlways502 int32
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitsAlways502, 1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, "<html>bad gateway</html>")
	}))
	defer srv2.Close()

	_, err = cl.postXML(srv2.URL+"/keep.cgi", "<request><hello>1</hello></request>")
	if err == nil || !strings.Contains(err.Error(), "HTTP=502") {
		t.Fatalf("expected HTTP=502 error, got: %v", err)
	}
	if atomic.LoadInt32(&hitsAlways502) != 6 {
		t.Fatalf("hitsAlways502 = %d, want 6", hitsAlways502)
	}

	// 10c. HTTP 200 + Error-Code=12 属于业务拒绝，绝不能重试
	var hitsEC12 int32
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitsEC12, 1)
		w.Header().Set("Error-Code", "12")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv3.Close()

	_, err = cl.postXML(srv3.URL+"/keep.cgi", "<request><hello>1</hello></request>")
	if err == nil || !strings.Contains(err.Error(), "HTTP=200 Error-Code=12") {
		t.Fatalf("expected HTTP=200 Error-Code=12, got: %v", err)
	}
	if atomic.LoadInt32(&hitsEC12) != 1 {
		t.Fatalf("hitsEC12 = %d, want 1 (must not retry app errors)", hitsEC12)
	}

	// 10d. probeOneTicketURL: 502 -> 502 -> 200 (64B) 在重试内成功，不触发 probeNext 跳过活节点
	var hitsProbe int32
	wantPayload := bytes.Repeat([]byte("A"), 64)
	srv4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hitsProbe, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, "<html>502</html>")
			return
		}
		w.Header().Set("Error-Code", "200")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wantPayload)
	}))
	defer srv4.Close()

	gotData, st, err := cl.probeOneTicketURL(srv4.URL+"/ticket.cgi", 2*time.Second, 5*time.Second)
	if err != nil || st != probeOK || !bytes.Equal(gotData, wantPayload) {
		t.Fatalf("probeOneTicketURL = (len=%d, st=%d, err=%v), want probeOK 64B", len(gotData), st, err)
	}
	if atomic.LoadInt32(&hitsProbe) != 3 {
		t.Fatalf("hitsProbe = %d, want 3", hitsProbe)
	}
}

// 11. 物理网卡与 TUN/VPN/Fake-IP 分类测试
func TestAdapterClassificationAndFakeIP(t *testing.T) {
	if !isFakeIP(net.ParseIP("198.18.0.1")) || !isFakeIP(net.ParseIP("198.19.255.254")) {
		t.Fatal("198.18.0.0/15 should be classified as Fake-IP")
	}
	if isFakeIP(net.ParseIP("10.20.30.40")) || isFakeIP(net.ParseIP("198.20.0.1")) {
		t.Fatal("non-Fake-IP falsely classified as Fake-IP")
	}

	cases := []struct {
		name, desc, ip, mac string
		ifType              uint32
		wantPhys, wantTUN   bool
	}{
		{"WLAN", "Intel(R) Wi-Fi 6E AX211 160MHz", "10.20.30.40", "02-00-5E-10-20-30", 71, true, false},
		{"以太网", "Realtek PCIe GbE Family Controller", "172.16.10.22", "02-00-5E-10-20-31", 6, true, false},
		{"Clash", "Meta Tunnel Wintun Userspace Tunnel", "198.18.0.1", "00-FF-11-22-33-44", 53, false, true},
		{"sing-box", "sing-box Tun Adapter", "172.19.0.1", "02-00-00-00-00-01", 53, false, true},
		{"Tailscale", "Tailscale Tunnel", "169.254.1.10", "", 53, false, true},
		{"ZeroTier One", "ZeroTier Virtual Port", "10.244.0.99", "02-00-5E-10-20-32", 6, false, false},
		{"vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", "172.31.0.1", "00-15-5D-00-00-01", 6, false, false},
	}
	for _, tc := range cases {
		phys, tun, reason := classifyAdapter(tc.name, tc.desc, tc.ip, tc.mac, tc.ifType)
		if phys != tc.wantPhys || tun != tc.wantTUN {
			t.Fatalf("classifyAdapter(%s/%s): got (phys=%v, tun=%v, reason=%q), want (%v, %v)",
				tc.name, tc.desc, phys, tun, reason, tc.wantPhys, tc.wantTUN)
		}
	}
}

// 12. 真实 Windows 宿主网卡枚举 & IP_UNICAST_IF setsockopt(htonl) 实测
func TestEnumerateAdaptersAndUnicastIfLive(t *testing.T) {
	adapters := EnumerateAdapters()
	if len(adapters) == 0 {
		t.Fatal("EnumerateAdapters returned empty list")
	}
	var phys *AdapterInfo
	for i := range adapters {
		a := adapters[i]
		if a.IfIndex == 0 || a.Name == "" {
			t.Fatalf("invalid adapter entry: %+v", a)
		}
		if a.IP4 != "" && net.ParseIP(a.IP4) == nil {
			t.Fatalf("malformed IP4 from struct offset: %+v", a)
		}
		if a.IsPhysical && a.IsUp && a.IP4 != "" && phys == nil {
			aa := a
			phys = &aa
		}
	}
	if phys == nil {
		t.Log("no up physical adapter in current environment, skipping setsockopt bind check")
		return
	}
	d := &net.Dialer{
		Timeout: 2 * time.Second,
		Control: func(_, _ string, rc syscall.RawConn) error {
			var sockErr error
			if err := rc.Control(func(fd uintptr) {
				sockErr = SetSocketUnicastIf4(fd, phys.IfIndex)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	_ = d
	lc := net.ListenConfig{
		Control: d.Control,
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", phys.IP4+":0")
	if err != nil {
		t.Fatalf("ListenPacket with IP_UNICAST_IF(ifIndex=%d, ip=%s) failed: %v", phys.IfIndex, phys.IP4, err)
	}
	_ = pc.Close()
}

// 13. HTML Meta Refresh 与 JS 重定向提取 (跨校 AC 兼容)
func TestHTMLAndJSRedirectExtraction(t *testing.T) {
	html1 := `<html><head><meta http-equiv="refresh" content="0;url=http://125.88.59.131:10001/?wlanuserip=10.1.2.3&amp;wlanacip=203.0.113.3"></head></html>`
	tgt1, kind1 := extractRedirectFromHTML(html1, "http://27.159.75.27/")
	if kind1 != "meta-refresh" || tgt1 != "http://125.88.59.131:10001/?wlanuserip=10.1.2.3&wlanacip=203.0.113.3" {
		t.Fatalf("meta1: got (%q, %q)", tgt1, kind1)
	}

	html2 := `<html><head><META content="0; URL=/index.cgi?wlanuserip=10.9.8.7&wlanacip=198.51.100.2" http-equiv=Refresh></head></html>`
	tgt2, kind2 := extractRedirectFromHTML(html2, "http://203.0.113.212:7001/portal")
	if kind2 != "meta-refresh" || tgt2 != "http://203.0.113.212:7001/index.cgi?wlanuserip=10.9.8.7&wlanacip=198.51.100.2" {
		t.Fatalf("meta2 relative: got (%q, %q)", tgt2, kind2)
	}

	html3 := `<script>window.location.replace('http://enet.10000.gd.cn:10001/?wlanuserip=10.5.6.7&wlanacip=198.51.100.1');</script>`
	tgt3, kind3 := extractRedirectFromHTML(html3, "http://223.5.5.5/")
	if kind3 != "js-redirect" || tgt3 != "http://enet.10000.gd.cn:10001/?wlanuserip=10.5.6.7&wlanacip=198.51.100.1" {
		t.Fatalf("js redirect: got (%q, %q)", tgt3, kind3)
	}
}

// 14. 多跳重定向 + 自动识别 school/domain/area + <server-clusters> 解析 (零手工参数)
func TestMultiHopAndAutoSchoolDiscovery(t *testing.T) {
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/hop1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<html><meta http-equiv="refresh" content="0;url=%s/hop2?wlanuserip=10.22.33.44&amp;wlanacip=198.51.100.10"></html>`, srvURL)
	})
	mux.HandleFunc("/hop2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("schoolid", "999")
		w.Header().Set("domain", "exampleu")
		w.Header().Set("area", "020")
		w.Header().Set("Location", srvURL+"/index.cgi?wlanuserip=10.22.33.44&wlanacip=198.51.100.10&portal_node=http://125.88.59.131:10002")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/index.cgi", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<HTML><!--//config.campus.js.chinatelecom.com <config><ticket-url><![CDATA[%s/ticket.cgi?wlanuserip=10.22.33.44&wlanacip=198.51.100.10]]></ticket-url><auth-url><![CDATA[%s/auth.cgi]]></auth-url><state-url><![CDATA[%s/state.cgi]]></state-url><server-clusters servers="203.0.113.212:7001,203.0.113.141:7001" weights="1,1"/></config>//config.campus.js.chinatelecom.com--></HTML>`,
			srvURL, srvURL, srvURL)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	cl := NewClient("13800138000", "secret123", "", "", "")
	if err := cl.extractIndexParams(srvURL + "/hop1?wlanuserip=10.22.33.44&wlanacip=198.51.100.10"); err != nil {
		t.Fatalf("extractIndexParams: %v", err)
	}
	cl.GetEConfig(srvURL + "/hop1?wlanuserip=10.22.33.44&wlanacip=198.51.100.10")

	if cl.school != "999" || cl.domain != "exampleu" || cl.area != "020" {
		t.Fatalf("auto school mismatch: school=%q domain=%q area=%q", cl.school, cl.domain, cl.area)
	}
	if cl.portalNode != "http://125.88.59.131:10002" {
		t.Fatalf("portalNode = %q", cl.portalNode)
	}
	if !strings.HasPrefix(cl.ticketURL, srvURL+"/ticket.cgi") || !strings.HasPrefix(cl.authURL, srvURL+"/auth.cgi") {
		t.Fatalf("EConfig URLs mismatch: ticket=%q auth=%q", cl.ticketURL, cl.authURL)
	}
	if len(cl.clusterServers) < 2 {
		t.Fatalf("expected clusterServers parsed, got: %v", cl.clusterServers)
	}
	if len(cl.diag.Hops()) != 3 {
		t.Fatalf("expected 3 redirect hops recorded, got %d", len(cl.diag.Hops()))
	}
}

// 15. 服务端错误解码与 Issue/日志严格脱敏测试
func TestErrorCodeFormattingAndRedaction(t *testing.T) {
	ci := &dynAesCipher{
		key1: []byte("0123456789abcdef0123456789abcdef"),
		iv:   []byte("fedcba9876543210"),
	}
	enc, err := ci.Encrypt([]byte(`<response><err-msg>账号余额不足或密码错误</err-msg></response>`))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	cl := NewClient("13800138000", "SuperSecret99", "888", "campusdemo", "0759")
	ferr := cl.formatServerError(200, "101", []byte(enc), ci)
	if !strings.Contains(ferr.Error(), "Error-Code=101") || !strings.Contains(ferr.Error(), "账号余额不足或密码错误") {
		t.Fatalf("formatServerError mismatch: %v", ferr)
	}

	if m := MaskAccount("13800138000"); m != "<REDACTED>" {
		t.Fatalf("MaskAccount leaked info: %q", m)
	}

	rawSensitive := `<request><passwd>SuperSecret99</passwd><userid>13800138000</userid><ticket>0ee37c33d8364e8dd13fc3de4d0cfd05</ticket></request>
Set-Cookie: JSESSIONID=SECRET_COOKIE_12345; Path=/
001@1ADB31EF35E541977931436C1B4A65EB16110C24EF682833956F9D8EBD3B01C7$ABA03E9C-E7E3-4AD0-94F9-4224DAA975C4]
校园网出口: 10.20.30.40 (ifIndex=4 WLAN) MAC=02-00-5E-10-20-30 GW=10.20.30.254
检测到需要认证: http://203.0.113.141:7001/index.cgi?wlanuserip=10.20.30.40&wlanacip=198.51.100.245&schoolid=888&domain=campusdemo&area=0759
登录成功 keepURL=http://203.0.113.142:7001/keep.cgi 心跳周期=300s (学校=888 域名=campusdemo 区号=0759)
ZeroTier One [a1b2c3d4e5f60718] DNS=203.0.113.53 Error-Code=0 HTTP=200 http://27.159.75.27/`

	redacted := SanitizeDiagnosticText(rawSensitive, "SuperSecret99", "13800138000")
	for _, leak := range []string{"SuperSecret99", "13800138000", "138****8000", "SECRET_COOKIE_12345", "d8364e8dd13fc3de4d0cfd05", "1ADB31EF35E54197"} {
		if strings.Contains(redacted, leak) {
			t.Fatalf("sensitive string leaked after SanitizeDiagnosticText: %q in:\n%s", leak, redacted)
		}
	}

	cl.userIP = "10.20.30.40"
	cl.acIP = "198.51.100.245"
	cl.mac = "02-00-5E-10-20-30"
	cl.nicName = "WLAN"
	cl.srcIfIndex = 4
	cl.keepURL = "http://203.0.113.142:7001/keep.cgi"
	cl.portalNode = "http://203.0.113.212:7001"
	snap := cl.Snapshot()
	snap.RedirectHops = []RedirectHop{
		{
			URL:      "http://203.0.113.141:7001/index.cgi?wlanuserip=10.20.30.40&wlanacip=198.51.100.245",
			Status:   200,
			Kind:     "econfig",
			School:   "888",
			Domain:   "campusdemo",
			Area:     "0759",
			Location: "http://203.0.113.212:7001/auth.cgi",
			RTTMs:    22,
		},
	}
	adapters := []AdapterInfo{
		{
			IfIndex:    4,
			Name:       "WLAN",
			TypeLabel:  "Wi-Fi",
			IsPhysical: true,
			IsUp:       true,
			IP4:        "10.20.30.40",
			Gateway:    "10.20.30.254",
			MAC:        "02-00-5E-10-20-30",
			DNSServers: []string{"203.0.113.53", "202.96.128.86"},
		},
		{
			IfIndex:   6,
			Name:      "ZeroTier One [a1b2c3d4e5f60718]",
			TypeLabel: "Virtual",
			IsUp:      true,
			IP4:       "10.244.0.99",
		},
	}
	doc := &DoctorReport{
		GeneratedAt: "2026-11-26 01:40:00",
		Checks: []DoctorCheck{
			{Name: "物理直连探测", Status: "pass", RTTMs: 41, Detail: "http://27.159.75.27/ HTTP 403 | DNS 203.0.113.53"},
		},
	}
	logs := []LogEntry{{Time: "12:00:00", Level: "INFO", Stage: "auth", Message: rawSensitive}}
	wires := []WireEntry{{Time: "12:00:00", Method: "POST", URL: "http://203.0.113.141:7001/auth.cgi", Status: 200, ErrorCode: "0", BodyPreview: rawSensitive}}

	md := BuildIssueMarkdown(snap, ProxyEnvInfo{TUNActive: true, TUNAdapters: []string{"Tailscale"}}, adapters, doc, logs, wires, "13800138000", "SuperSecret99")
	js := BuildIssueJSON(snap, ProxyEnvInfo{TUNActive: true, TUNAdapters: []string{"Tailscale"}}, adapters, doc, logs, wires, "13800138000", "SuperSecret99")

	for _, leak := range []string{
		"SuperSecret99", "13800138000", "138****8000", "8000",
		"888", "campusdemo", "0759",
		"02-00-5E-10-20-30", "10.20.30.40", "10.20.30.254", "198.51.100.245",
		"203.0.113.141", "203.0.113.142", "203.0.113.212", "203.0.113.53",
		"10.244.0.99", "a1b2c3d4e5f60718",
		"SECRET_COOKIE_12345", "0ee37c", "d8364e8dd13fc3de4d0cfd05", "1ADB31EF35E54197",
	} {
		if strings.Contains(md, leak) {
			t.Fatalf("sensitive string %q leaked in Issue Markdown:\n%s", leak, md)
		}
		if strings.Contains(string(js), leak) {
			t.Fatalf("sensitive string %q leaked in Issue JSON:\n%s", leak, string(js))
		}
	}
	for _, keep := range []string{"27.159.75.27", "/auth.cgi", ":7001"} {
		if !strings.Contains(md, keep) || !strings.Contains(string(js), keep) {
			t.Fatalf("diagnostic marker %q missing after sanitization", keep)
		}
	}
	var parsed map[string]any
	if err := json.Unmarshal(js, &parsed); err != nil {
		t.Fatalf("BuildIssueJSON produced invalid JSON: %v\n%s", err, string(js))
	}
}

// 17. term.cgi 静默不回包 / 无体响应头 / 立即断连容错与 Logout 幂等清理验证
func TestPostTermSilentDropAndHeaderOnly(t *testing.T) {
	origSess, sessErr := os.ReadFile(sessionFile)
	if sessErr == nil {
		defer func() { _ = os.WriteFile(sessionFile, origSess, 0600) }()
	} else {
		defer func() { _ = os.Remove(sessionFile) }()
	}

	ci := &dynAesCipher{
		key1: []byte("0123456789abcdef0123456789abcdef"),
		iv:   []byte("fedcba9876543210"),
	}

	serveCase := func(mode string) (string, func()) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			switch mode {
			case "silent":
				time.Sleep(4 * time.Second)
			case "header-only":
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nError-Code: 0\r\n\r\n")
				time.Sleep(4 * time.Second)
			case "eof":
				// 收到 POST 后立即断链
			}
		}()
		return "http://" + ln.Addr().String() + "/term.cgi", func() {
			_ = ln.Close()
			<-done
		}
	}

	// Case A: 服务端收到注销包后静默不回包
	urlSilent, stopSilent := serveCase("silent")
	defer stopSilent()
	clA := NewClient("13800138000", "Pass123", "888", "campusdemo", "0759")
	clA.diag = NewDiagHub()
	clA.cipher = ci
	clA.ticket = "tk-silent"
	clA.termURL = urlSilent
	clA.keepURL = portalRoot(urlSilent) + "/keep.cgi"
	clA.saveSession()
	t0 := time.Now()
	clA.Logout()
	elapsed := time.Since(t0)
	if elapsed > 2800*time.Millisecond {
		t.Fatalf("silent term.cgi took too long: %v", elapsed)
	}
	if _, err := os.Stat(sessionFile); !os.IsNotExist(err) {
		t.Fatalf("session.txt should be removed on silent Logout, err=%v", err)
	}
	if clA.ticket != "" || clA.termURL != "" || clA.keepURL != "" || clA.cipher != nil {
		t.Fatalf("Logout did not clear client session fields")
	}
	// 第二次调用必须幂等且瞬时返回
	t1 := time.Now()
	clA.Logout()
	if time.Since(t1) > 100*time.Millisecond {
		t.Fatalf("second Logout should be instant no-op")
	}

	// Case B: 仅返回 HTTP 响应头而未关闭连接且无 Content-Length
	urlHdr, stopHdr := serveCase("header-only")
	defer stopHdr()
	clB := NewClient("13800138000", "Pass123", "888", "campusdemo", "0759")
	clB.diag = NewDiagHub()
	tHdr := time.Now()
	ack, err := clB.postTerm(urlHdr, AlgoAesCbc, "cid-b", ci, "tk-hdr", 1)
	if err != nil || !ack {
		t.Fatalf("header-only postTerm got (ack=%v, err=%v), want (true, nil)", ack, err)
	}
	if time.Since(tHdr) > 800*time.Millisecond {
		t.Fatalf("header-only postTerm waited for body/EOF: %v", time.Since(tHdr))
	}

	// Case C: 收到 POST 后服务端立即 EOF 断连
	urlEOF, stopEOF := serveCase("eof")
	defer stopEOF()
	ack, err = clB.postTerm(urlEOF, AlgoAesCbc, "cid-c", ci, "tk-eof", 1)
	if err != nil || ack {
		t.Fatalf("eof postTerm got (ack=%v, err=%v), want (false, nil)", ack, err)
	}
}

// 18. daemon handleDisconnect 并发安全与 retired Client 不得回写过时 SSE 状态
func TestDaemonDisconnectAndDetachedStateGuard(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	srv := newDaemonServer()
	old := NewClient("13800138000", "Pass123", "888", "campusdemo", "0759")
	old.diag = srv.diag
	old.setState(StateConnected, "online", "")

	// 注册 SSE 订阅校验 detached 客户端静默特性
	subID, ch := srv.diag.Subscribe()
	defer srv.diag.Unsubscribe(subID)

	old.detached.Store(true)
	old.setState(StateError, "error", "stale-error")
	select {
	case ev := <-ch:
		t.Fatalf("detached client leaked SSE event: %+v", ev)
	case <-time.After(30 * time.Millisecond):
	}

	// 校验无回包服务端下 handleDisconnect 正常回到 disconnected
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		time.Sleep(4 * time.Second)
	}()

	active := NewClient("13800138000", "Pass123", "888", "campusdemo", "0759")
	active.diag = srv.diag
	active.cipher = &dynAesCipher{
		key1: []byte("0123456789abcdef0123456789abcdef"),
		iv:   []byte("fedcba9876543210"),
	}
	active.ticket = "tk-live"
	active.termURL = "http://" + ln.Addr().String() + "/term.cgi"
	active.setState(StateConnected, "online", "")
	srv.mu.Lock()
	srv.client = active
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/disconnect", nil)
	rr := httptest.NewRecorder()
	srv.handleDisconnect(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleDisconnect HTTP=%d body=%s", rr.Code, rr.Body.String())
	}
	if snap := active.Snapshot(); snap.State != StateDisconnected {
		t.Fatalf("expected StateDisconnected after handleDisconnect, got %q", snap.State)
	}
	if !active.detached.Load() {
		t.Fatalf("expected active client to be marked detached after disconnect")
	}
}

func startMockUDPDNSServer(t *testing.T, answerIP net.IP, blackhole bool) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			if blackhole || n < 12 || answerIP == nil || answerIP.To4() == nil {
				continue
			}
			// 构造最小合法 RFC1035 A 记录响应: 复制 ID + Question, 追加 0xC00C 指针 A 记录
			qEnd := 12
			for qEnd < n && buf[qEnd] != 0 {
				qEnd += 1 + int(buf[qEnd])
			}
			if qEnd+5 > n {
				continue
			}
			qEnd += 5 // null + QTYPE(2) + QCLASS(2)
			resp := make([]byte, 0, qEnd+16)
			resp = append(resp, buf[0], buf[1]) // ID
			resp = append(resp, 0x81, 0x80)     // QR=1, RD=1, RA=1, NOERROR
			resp = append(resp, 0x00, 0x01)     // QDCOUNT=1
			resp = append(resp, 0x00, 0x01)     // ANCOUNT=1
			resp = append(resp, 0x00, 0x00, 0x00, 0x00)
			resp = append(resp, buf[12:qEnd]...)
			ip4 := answerIP.To4()
			resp = append(resp,
				0xC0, 0x0C, // Name pointer to offset 12
				0x00, 0x01, // TYPE = A
				0x00, 0x01, // CLASS = IN
				0x00, 0x00, 0x00, 0x3C, // TTL = 60s
				0x00, 0x04, // RDLENGTH = 4
				ip4[0], ip4[1], ip4[2], ip4[3],
			)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
		<-done
	}
}

// 19. 并发 DNS 竞速（黑洞 DNS + Fake-IP DNS + 有效 DNS）与内置保底节点回退
func TestRacePinnedDNSAndCustomDNSFallback(t *testing.T) {
	bhAddr, stopBH := startMockUDPDNSServer(t, nil, true)
	defer stopBH()
	fakeAddr, stopFake := startMockUDPDNSServer(t, net.IPv4(198, 18, 0, 66), false)
	defer stopFake()
	validAddr, stopValid := startMockUDPDNSServer(t, net.IPv4(125, 88, 59, 131), false)
	defer stopValid()

	t0 := time.Now()
	ips, srv, err := racePinnedDNS4NoCache(context.Background(), nil, 0, []string{bhAddr, fakeAddr, validAddr}, "enet.10000.gd.cn")
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("racePinnedDNS4NoCache failed: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "125.88.59.131" || srv != validAddr {
		t.Fatalf("got ips=%v srv=%q, want [125.88.59.131] from %q", ips, srv, validAddr)
	}
	if elapsed > 600*time.Millisecond {
		t.Fatalf("race took too long despite valid responder: %v", elapsed)
	}

	// 验证全部是黑洞 / Fake-IP 且无有效应答时被正确拒绝
	ctxFail, cancelFail := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancelFail()
	if _, _, ferr := racePinnedDNS4NoCache(ctxFail, nil, 0, []string{bhAddr, fakeAddr}, "enet.10000.gd.cn"); ferr == nil {
		t.Fatalf("expected error when only blackhole + Fake-IP DNS exist")
	}

	// 验证所有外部 DNS 被超时拦截时，enet.10000.gd.cn 自动回退至内置真实调度节点 IP
	ctxTiny, cancelTiny := context.WithTimeout(context.Background(), 2*time.Millisecond)
	defer cancelTiny()
	fbIPs, fbSrc, fbErr := resolvePinnedIP4List(ctxTiny, nil, 0, []string{bhAddr}, "enet.10000.gd.cn")
	if fbErr != nil || fbSrc != "builtin-fallback" || len(fbIPs) == 0 {
		t.Fatalf("expected builtin-fallback IPs, got ips=%v src=%q err=%v", fbIPs, fbSrc, fbErr)
	}
}

// 20. 8s 离线哨兵立即捕获强认证重定向/断网唤醒，及心跳会话失效瞬时判死
func TestWatchdogDetectsCaptiveDropAndInstantHeartbeatOffline(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Location", "http://125.88.59.131:10001/?wlanuserip=10.20.30.40&wlanacip=198.51.100.245")
		w.WriteHeader(http.StatusFound)
	}))
	defer ts.Close()

	cl := NewClient("13800138000", "Pass123", "888", "campusdemo", "0759")
	cl.diag = NewDiagHub()
	cl.watchdogURL = ts.URL
	cl.watchdogInterval = 35 * time.Millisecond

	t0 := time.Now()
	ok, capDrop, why := cl.sleepWithWatchdog(context.Background(), 10*time.Second, 0, "")
	elapsed := time.Since(t0)
	if ok || !capDrop {
		t.Fatalf("expected captive drop wakeup (ok=%v, capDrop=%v, why=%q)", ok, capDrop, why)
	}
	if !strings.Contains(why, "125.88.59.131:10001") {
		t.Fatalf("unexpected captive reason: %q", why)
	}
	if elapsed > 1200*time.Millisecond {
		t.Fatalf("watchdog waited too long to wake on captive drop: %v", elapsed)
	}

	// 网络连续 2 次不可达时同样快速唤醒供心跳确认
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	cl.watchdogURL = deadURL
	t1 := time.Now()
	ok2, capDrop2, _ := cl.sleepWithWatchdog(context.Background(), 10*time.Second, 0, "")
	if ok2 || capDrop2 || time.Since(t1) > 1200*time.Millisecond {
		t.Fatalf("expected fast non-captive wake on dead probe, got ok=%v capDrop=%v elapsed=%v", ok2, capDrop2, time.Since(t1))
	}

	// 即时离线心跳错误分类断言
	instantCases := []error{
		errors.New("会话无效 | HTTP=200 Error-Code=12 body=\"\""),
		errors.New("未登录 | HTTP=200 Error-Code=300 body=\"\""),
		errors.New("解密失败 | HTTP=200 Error-Code=1 body=\"\""),
		errors.New("网关异常或无 Error-Code 响应 | HTTP=302 Error-Code= body=\"\""),
		errors.New("网关异常或无 Error-Code 响应 | HTTP=200 Error-Code= body=\"<!DOCTYPE HTML><html\""),
	}
	for _, tc := range instantCases {
		if !isInstantOfflineHeartbeatErr(tc) {
			t.Fatalf("expected instant offline match for %q", tc)
		}
	}
	transientCases := []error{
		errors.New("dial tcp4 203.0.113.142:7001: i/o timeout"),
		errors.New("校园网认证网关临时不可用 (HTTP 502 Bad Gateway) | HTTP=502 Error-Code= body=\"\""),
	}
	for _, tc := range transientCases {
		if isInstantOfflineHeartbeatErr(tc) {
			t.Fatalf("unexpected instant offline match for transient error %q", tc)
		}
	}
}

// 21. 校验 NAT 哨兵基准 IP (srcIP vs userIP)、OneShotForce 不污染持久配置与 resetSession 全量清理
func TestWatchdogNATAndOneShotForceGuard(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())

	cl := NewClient("13800138000", "Pass123", "", "", "")
	cl.srcIfIndex = 7
	cl.srcIP = net.IPv4(192, 168, 31, 88)
	cl.userIP = "10.20.30.40"
	cl.acIP = "198.51.100.245"
	ifIdx, localIP := cl.watchBaseNIC()
	if ifIdx != 7 || localIP != "192.168.31.88" {
		t.Fatalf("watchBaseNIC got (%d, %q), want (7, 192.168.31.88)", ifIdx, localIP)
	}

	cl.resetSession()
	if cl.srcIP != nil || cl.srcIfIndex != 0 || cl.userIP != "" || cl.acIP != "" || cl.nicName != "" || len(cl.nicDNS) != 0 {
		t.Fatalf("resetSession did not clear NIC/session state: srcIP=%v ifIdx=%d userIP=%q acIP=%q",
			cl.srcIP, cl.srcIfIndex, cl.userIP, cl.acIP)
	}

	srv := newDaemonServer()
	if !srv.cfg.PrivacyMode {
		t.Fatalf("expected PrivacyMode to default to true")
	}
	if srv.cfg.ForceReauth {
		t.Fatalf("expected ForceReauth to default to false")
	}

	// 单次点击“强制重连” (OneShotForce=true) 不应将 ForceReauth=true 持久化到 config.json
	bodyOneShot := `{"account":"13800138000","password":"Pass123","rememberPassword":false,"force":true,"oneShotForce":true}`
	rr1 := httptest.NewRecorder()
	srv.handleConnect(rr1, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(bodyOneShot)))
	srv.mu.Lock()
	srv.stopActiveLocked(true)
	persistedAfterOneShot := srv.cfg.ForceReauth
	srv.mu.Unlock()
	if rr1.Code != http.StatusOK || persistedAfterOneShot {
		t.Fatalf("OneShotForce leaked into cfg.ForceReauth: code=%d persisted=%v", rr1.Code, persistedAfterOneShot)
	}

	// 普通连接勾选 chk-force (OneShotForce=false) 应同步保存配置
	bodySticky := `{"account":"13800138000","password":"Pass123","rememberPassword":false,"force":true,"oneShotForce":false}`
	rr2 := httptest.NewRecorder()
	srv.handleConnect(rr2, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(bodySticky)))
	srv.mu.Lock()
	srv.stopActiveLocked(true)
	persistedAfterSticky := srv.cfg.ForceReauth
	srv.mu.Unlock()
	if rr2.Code != http.StatusOK || !persistedAfterSticky {
		t.Fatalf("expected sticky ForceReauth=true when OneShotForce=false: code=%d persisted=%v", rr2.Code, persistedAfterSticky)
	}
}

// 22. 验证配置阶段死节点快速故障转移、死节点降权、acIP 隔离多节点缓存与可取消上下文
func TestConfigFastFailoverAndDeadPortalDemotion(t *testing.T) {
	origCache, cacheErr := os.ReadFile(portalCacheFile)
	if cacheErr == nil {
		defer func() { _ = os.WriteFile(portalCacheFile, origCache, 0644) }()
	} else {
		defer func() { _ = os.Remove(portalCacheFile) }()
	}

	// 阻塞型服务端（接收 TCP 后不返回 HTTP 响应）
	stallLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer stallLn.Close()
	stallDone := make(chan struct{})
	go func() {
		defer close(stallDone)
		for {
			c, aerr := stallLn.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				time.Sleep(12 * time.Second)
			}(c)
		}
	}()
	deadBase := "http://" + stallLn.Addr().String()

	hop1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("schoolid", "888")
		w.Header().Set("domain", "campusdemo")
		w.Header().Set("area", "0759")
		w.Header().Set("Location", deadBase+"/index.cgi?wlanuserip=10.20.30.40&wlanacip=198.51.100.245")
		w.WriteHeader(http.StatusFound)
	}))
	defer hop1.Close()

	cl := NewClient("13800138000", "Pass123", "", "", "")
	cl.diag = NewDiagHub()
	cl.userIP = "10.20.30.40"
	cl.acIP = "198.51.100.245"

	t0 := time.Now()
	cl.walkRedirectAndConfig(hop1.URL + "/?wlanuserip=10.20.30.40&wlanacip=198.51.100.245")
	elapsed := time.Since(t0)
	if elapsed > 4800*time.Millisecond {
		t.Fatalf("walkRedirectAndConfig took too long on stalled node: %v (want < 4.8s)", elapsed)
	}
	if !cl.isPortalDead(deadBase) {
		t.Fatalf("expected stalled portal %q to be marked in deadPortals", deadBase)
	}
	if cl.school != "888" || cl.domain != "campusdemo" || cl.area != "0759" {
		t.Fatalf("lost header school params after dead hop: %q %q %q", cl.school, cl.domain, cl.area)
	}

	// 验证上下文取消可立即打断阻塞配置请求 (< 500ms)
	cancelCtx, cancelFn := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancelFn()
	cl.mu.Lock()
	cl.runCtx = cancelCtx
	cl.mu.Unlock()
	tCancel := time.Now()
	cl.walkRedirectAndConfig(deadBase + "/index.cgi?wlanuserip=10.20.30.40&wlanacip=198.51.100.245")
	if time.Since(tCancel) > 600*time.Millisecond {
		t.Fatalf("walkRedirectAndConfig did not abort fast on ctx cancel: %v", time.Since(tCancel))
	}
	cl.mu.Lock()
	cl.runCtx = nil
	cl.mu.Unlock()

	// 验证 multi-node portal_cache.txt 与跨校 AC 隔离
	cl.keepURL = "http://203.0.113.142:7001/keep.cgi"
	cl.clusterServers = []string{"http://203.0.113.212:7001", deadBase}
	cl.savePortalCache("http://enet.10000.gd.cn:10001/ticket.cgi")

	sameAC := loadPortalCache("198.51.100.245")
	if len(sameAC) < 3 || sameAC[0] != "http://203.0.113.142:7001" {
		t.Fatalf("unexpected loadPortalCache sameAC: %v", sameAC)
	}
	for _, u := range sameAC {
		if u == deadBase {
			t.Fatalf("dead portal %q should not be persisted in cache: %v", deadBase, sameAC)
		}
	}
	if diffAC := loadPortalCache("198.51.100.2"); len(diffAC) != 0 {
		t.Fatalf("expected cross-AC cache to be ignored, got: %v", diffAC)
	}

	// 验证 candidateTicketURLs 三层优先级: 健康 :7001 -> :10001 调度 -> 死节点垫底
	cl.portalPage = ""
	cl.ticketURL = "http://enet.10000.gd.cn:10001/ticket.cgi?wlanuserip=10.20.30.40&wlanacip=198.51.100.245"
	cands := cl.candidateTicketURLs()
	idx7001, idx10001, idxDead := -1, -1, -1
	for i, u := range cands {
		switch {
		case idx7001 < 0 && strings.HasPrefix(u, "http://203.0.113.142:7001/ticket.cgi"):
			idx7001 = i
		case idx10001 < 0 && strings.HasPrefix(u, "http://enet.10000.gd.cn:10001/ticket.cgi"):
			idx10001 = i
		case idxDead < 0 && strings.HasPrefix(u, deadBase+"/ticket.cgi"):
			idxDead = i
		}
	}
	if idx7001 < 0 || idx10001 < 0 || idxDead < 0 || !(idx7001 < idx10001 && idx10001 < idxDead) {
		t.Fatalf("bad candidateTicketURLs priority (7001=%d, 10001=%d, dead=%d) in %v",
			idx7001, idx10001, idxDead, cands)
	}
}

// 23. 致命账号/策略错误 vs 瞬态网络错误/无网卡等待分类断言
func TestAuthErrorClassification(t *testing.T) {
	fatalCases := []error{
		errors.New("认证失败: 账号不存在或密码错误 (Error-Code=101) | HTTP=200 Error-Code=101 body=\"\""),
		errors.New("认证失败: Error-Code=105 | HTTP=200 Error-Code=105"),
		errors.New("认证失败: Error-Code=110 | HTTP=200 Error-Code=110"),
		errors.New("认证失败: Error-Code=201 | HTTP=200 Error-Code=201"),
		errors.New("认证失败: Error-Code=100 | HTTP=200 Error-Code=100"),
		errors.New("请输入密码"),
	}
	for _, err := range fatalCases {
		if !isFatalAuthErr(err) {
			t.Fatalf("expected fatal auth match for %q", err)
		}
	}

	transientCases := []error{
		errors.New("认证失败: 服务端解密失败 | HTTP=200 Error-Code=1 body=\"\""),
		errors.New("认证失败: 票据过期 | HTTP=200 Error-Code=12 body=\"\""),
		errors.New("认证失败: dial tcp4 203.0.113.141:7001: i/o timeout"),
		errors.New("认证失败: HTTP=502 Bad Gateway"),
		errors.New("认证失败: x86emu step limit exceeded"),
	}
	for _, err := range transientCases {
		if isFatalAuthErr(err) {
			t.Fatalf("transient error %q must NOT be classified as fatal", err)
		}
	}

	if !isNoNetworkDetectErr(errors.New("未检测到可用的物理网络接口 (已自动排除 TUN/VPN 虚拟网卡)")) {
		t.Fatalf("expected isNoNetworkDetectErr=true for missing physical NIC")
	}
	if !isNoNetworkDetectErr(errors.New("未检测到需要认证的校园网接口")) {
		t.Fatalf("expected isNoNetworkDetectErr=true for undetected campus NIC")
	}
	if isNoNetworkDetectErr(fatalCases[0]) {
		t.Fatalf("credential error must not trigger boot wait")
	}
}

// 24. 并发读写 Client 会话状态与 Snapshot/candidateTicketURLs/Preflight（配合 go test -race 验证零数据竞态）
func TestClientSnapshotConcurrentRace(t *testing.T) {
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/hop1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("schoolid", "888")
		w.Header().Set("domain", "campusdemo")
		w.Header().Set("area", "0759")
		w.Header().Set("Location", srvURL+"/index.cgi?wlanuserip=10.20.30.40&wlanacip=198.51.100.245&portal_node=http://125.88.59.131:10002")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/index.cgi", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<HTML><!--//config.campus.js.chinatelecom.com <config><ticket-url><![CDATA[%s/ticket.cgi]]></ticket-url><auth-url><![CDATA[%s/auth.cgi]]></auth-url><state-url><![CDATA[%s/state.cgi]]></state-url><server-clusters servers="%s" weights="1"/></config>//config.campus.js.chinatelecom.com--></HTML>`,
			srvURL, srvURL, srvURL, strings.TrimPrefix(srvURL, "http://"))
	})
	mux.HandleFunc("/detect.html", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	cl := NewClient("13800138000", "Pass123", "", "", "")
	ci := &dynAesCipher{
		key1: []byte("0123456789abcdef0123456789abcdef"),
		iv:   []byte("fedcba9876543210"),
	}

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if i%5 == 0 {
					cl.resetSession()
				}
				cl.setSessionIPs("10.20.30.40", "198.51.100.245", false)
				cl.walkRedirectAndConfig(srvURL + "/hop1?wlanuserip=10.20.30.40&wlanacip=198.51.100.245")
				cl.applyDiscoveredSchool("888", "campusdemo", "0759")
				cl.setCipherAndFamily(AlgoAesCbc, "动态 AES-128-CBC", ci)
				cl.rebaseToPortal(srvURL + "/ticket.cgi?wlanuserip=10.20.30.40&wlanacip=198.51.100.245")
				cl.Preflight()
				cl.setState(StateConnecting, "negotiate", "")
			}
		}(g)
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				_ = cl.Snapshot()
				_ = cl.cdcHeaders()
				_ = cl.candidateTicketURLs()
				_, _ = cl.watchBaseNIC()
				_, _ = cl.getSessionIPs()
				_, _, _, _, _ = cl.getEndpointURLs()
			}
		}()
	}
	wg.Wait()
}

// 25. 切换账号防误用旧密码、认证成功前不覆盖已保存凭据、严格 HTTP Method 校验
func TestDaemonAccountSwitchAndDeferredCredentialSave(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())

	encOld, err := DPAPIProtect([]byte("OldPass123"))
	if err != nil {
		t.Fatalf("DPAPIProtect: %v", err)
	}
	initialCfg := defaultDaemonConfig()
	initialCfg.Account = "13800138000"
	initialCfg.RememberPassword = true
	initialCfg.EncryptedPass = encOld
	if err := saveDaemonConfig(initialCfg); err != nil {
		t.Fatalf("saveDaemonConfig: %v", err)
	}

	srv := newDaemonServer()
	srv.diag.AddLog("INFO", "init", "seed")

	// 1. 切换新账号但留空密码: 必须拒绝且保留原账号保存的密码
	bodySwitchEmpty := `{"account":"13900139000","password":"","useSavedPassword":true,"rememberPassword":true}`
	rrSwitch := httptest.NewRecorder()
	srv.handleConnect(rrSwitch, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(bodySwitchEmpty)))
	if rrSwitch.Code != http.StatusBadRequest || !strings.Contains(rrSwitch.Body.String(), "已切换账号") {
		t.Fatalf("expected 400 on switched account with empty password, got %d %s", rrSwitch.Code, rrSwitch.Body.String())
	}
	srv.mu.Lock()
	if srv.cfg.Account != "13800138000" || srv.cfg.EncryptedPass != encOld {
		srv.mu.Unlock()
		t.Fatalf("switched account mutated saved credentials: acct=%q encChanged=%v", srv.cfg.Account, srv.cfg.EncryptedPass != encOld)
	}
	srv.mu.Unlock()

	// 2. 切换新账号并填写新密码: 在登录真正成功 (onAuthSuccess) 之前不得覆盖原账号配置
	bodySwitchPwd := `{"account":"13900139000","password":"NewPass456","useSavedPassword":false,"rememberPassword":true}`
	rrNew := httptest.NewRecorder()
	srv.handleConnect(rrNew, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(bodySwitchPwd)))
	if rrNew.Code != http.StatusOK {
		t.Fatalf("expected 200 on switched account with explicit password, got %d %s", rrNew.Code, rrNew.Body.String())
	}
	srv.mu.Lock()
	cl := srv.client
	acctBeforeSuccess := srv.cfg.Account
	encBeforeSuccess := srv.cfg.EncryptedPass
	srv.mu.Unlock()
	if acctBeforeSuccess != "13800138000" || encBeforeSuccess != encOld {
		t.Fatalf("credentials overwritten BEFORE auth success: acct=%q", acctBeforeSuccess)
	}

	// 停止后台真实探网后再模拟触发 onAuthSuccess，验证成功后正确覆盖保存新凭据
	srv.mu.Lock()
	if srv.cancelRun != nil {
		srv.cancelRun()
	}
	done := srv.runDone
	srv.mu.Unlock()
	if done != nil {
		<-done
	}
	if cl.onAuthSuccess == nil {
		t.Fatal("expected onAuthSuccess callback to be wired")
	}
	cl.detached.Store(false)
	cl.onAuthSuccess()

	srv.mu.Lock()
	acctAfterSuccess := srv.cfg.Account
	encAfterSuccess := srv.cfg.EncryptedPass
	srv.mu.Unlock()
	decNew, err := DPAPIUnprotect(encAfterSuccess)
	if err != nil || acctAfterSuccess != "13900139000" || string(decNew) != "NewPass456" {
		t.Fatalf("onAuthSuccess did not persist new credentials: acct=%q dec=%q err=%v", acctAfterSuccess, string(decNew), err)
	}

	// 3. HTTP Method 校验 (GET /api/shutdown -> 405, POST /api/state -> 405)
	rrShut := httptest.NewRecorder()
	srv.authMiddleware(srv.handleShutdown)(rrShut, httptest.NewRequest(http.MethodGet, "/api/shutdown", nil))
	if rrShut.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated shutdown = %d, want 401", rrShut.Code)
	}
	reqShut405 := httptest.NewRequest(http.MethodGet, "/api/shutdown", nil)
	reqShut405.Header.Set("X-GDPortal-Token", srv.token)
	rrShut405 := httptest.NewRecorder()
	srv.authMiddleware(srv.handleShutdown)(rrShut405, reqShut405)
	if rrShut405.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/shutdown = %d, want 405", rrShut405.Code)
	}
	// query token 必须失效 (401)
	rrQ := httptest.NewRecorder()
	srv.authMiddleware(srv.handleState)(rrQ, httptest.NewRequest(http.MethodGet, "/api/state?token="+srv.token, nil))
	if rrQ.Code != http.StatusUnauthorized {
		t.Fatalf("query token must be rejected (got %d, want 401)", rrQ.Code)
	}
}

// 26. 取票重试共享总时限预算，与 Error-Code=101 致命错误首轮即止
func TestTicketRetryBudgetAndFatalExit(t *testing.T) {
	origMax := ticketRetryMaxCycles
	origBudget := ticketRetryBudget
	origBackoffs := append([]time.Duration(nil), ticketRetryBackoffs...)
	defer func() {
		ticketRetryMaxCycles = origMax
		ticketRetryBudget = origBudget
		ticketRetryBackoffs = origBackoffs
	}()

	ticketRetryMaxCycles = 5
	ticketRetryBudget = 300 * time.Millisecond
	ticketRetryBackoffs = []time.Duration{200 * time.Millisecond}

	ci := &dynAesCipher{
		key1: []byte("0123456789abcdef0123456789abcdef"),
		iv:   []byte("fedcba9876543210"),
	}
	var ticketHits atomic.Int32
	var respEC atomic.Value
	respEC.Store("12")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/detect.html":
			w.WriteHeader(http.StatusOK)
		case "/ticket.cgi":
			n := ticketHits.Add(1)
			// 静态算法协商请求带 zeroAlgoID，返回静态响应
			if r.Header.Get("Algo-ID") == zeroAlgoID {
				body := make([]byte, 0, 4+32+1+36)
				body = append(body, 0, 0, 0, 32)
				body = append(body, make([]byte, 32)...)
				body = append(body, 36)
				body = append(body, []byte(AlgoAesCbc)...)
				w.Header().Set("Error-Code", "200")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body)
				return
			}
			_ = n
			w.Header().Set("Error-Code", respEC.Load().(string))
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cl := NewClient("13800138000", "Pass123", "888", "campusdemo", "0759")
	cl.cipher = ci
	cl.algoID = AlgoAesCbc
	cl.ticketURL = srv.URL + "/ticket.cgi"
	cl.econfigHost = hostOf(srv.URL)

	t0 := time.Now()
	_, _, err := cl.runNegotiateAndTicket(context.Background())
	elapsed := time.Since(t0)
	if err == nil {
		t.Fatal("expected ticket retry failure")
	}
	if elapsed > 1200*time.Millisecond {
		t.Fatalf("ticket retry exceeded shared budget: %v", elapsed)
	}

	// 致命 Error-Code=101 必须在第 1 轮取票失败后立即返回，不再等待下一轮重试
	ticketHits.Store(0)
	respEC.Store("101")
	ticketRetryBudget = 5 * time.Second
	tFatal := time.Now()
	_, _, errFatal := cl.runNegotiateAndTicket(context.Background())
	if !isFatalAuthErr(errFatal) {
		t.Fatalf("expected fatal auth error, got %v", errFatal)
	}
	if time.Since(tFatal) > 500*time.Millisecond {
		t.Fatalf("fatal Error-Code=101 retried instead of exiting immediately: %v", time.Since(tFatal))
	}
}

// 27. 轻量巡检 queryInterfaceIPv4Fast 与 checkNICChanged 状态校验
func TestFastWatchdogNICCheck(t *testing.T) {
	exists, _, _ := queryInterfaceIPv4Fast(0)
	if exists {
		t.Fatal("ifIndex=0 should not exist")
	}
	if changed, _ := checkNICChanged(0, "10.20.30.40"); changed {
		t.Fatal("empty baseIfIndex should not report change")
	}
	changed, why := checkNICChanged(9999999, "10.20.30.40")
	if !changed || !strings.Contains(why, "#9999999") {
		t.Fatalf("expected missing NIC to trigger change, got (%v, %q)", changed, why)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, f := range ifaces {
		if f.Index <= 0 || f.Flags&net.FlagLoopback != 0 || f.Flags&net.FlagUp == 0 {
			continue
		}
		ex, up, ips := queryInterfaceIPv4Fast(uint32(f.Index))
		if !ex || !up || len(ips) == 0 {
			continue
		}
		if chg, why2 := checkNICChanged(uint32(f.Index), ips[0]); chg {
			t.Fatalf("matching NIC IPv4 %s reported changed: %q", ips[0], why2)
		}
		if chg, _ := checkNICChanged(uint32(f.Index), "192.0.2.254"); !chg {
			t.Fatalf("mismatched NIC IPv4 should report changed for ifIndex=%d (actual=%v)", f.Index, ips)
		}
		return
	}
}




