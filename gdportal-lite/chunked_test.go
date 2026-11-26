package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestChunkedReadHTTPMessage: net.Pipe 发送 chunked 响应 (模拟 ticket.cgi EC=0 形态),
// 验证 readHTTPMessage 能解出完整 body (2026-11-25 实测 Go 读空 / Python 读到 272B)。
func TestChunkedReadHTTPMessage(t *testing.T) {
	payload := strings.Repeat("ED8D50FCBB00FDC3", 17) // 272B 大写 hex ASCII (=0x110, 与 chunk 头一致)
	resp := "HTTP/1.1 200 OK\r\n" +
		"Server: ******\r\n" +
		"Content-Type: text/html\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Error-Code: 0\r\n" +
		"Connection: close\r\n\r\n" +
		"110\r\n" + payload + "\r\n0\r\n\r\n"

	c1, c2 := net.Pipe()
	go func() {
		c2.SetDeadline(time.Now().Add(5 * time.Second))
		// 消费客户端可能的写入 (pipe 同步)
		go func() {
			tmp := make([]byte, 4096)
			for {
				if _, err := c2.Read(tmp); err != nil {
					return
				}
			}
		}()
		// 模拟服务器分两次发送 (头+部分 / 剩余) — 覆盖真实 TCP 分片场景
		s := []byte(resp)
		c2.Write(s[:len(s)-100])
		time.Sleep(10 * time.Millisecond)
		c2.Write(s[len(s)-100:])
	}()

	c1.SetDeadline(time.Now().Add(5 * time.Second))
	head, chunkedRaw, err := readHTTPMessage(c1)
	if err != nil {
		t.Fatalf("readHTTPMessage err: %v", err)
	}
	if !strings.Contains(string(head), "chunked") {
		t.Fatalf("头应含 chunked: %q", string(head))
	}
	body := dechunk(chunkedRaw)
	t.Logf("chunk 流 %dB → de-chunk 后 body %dB", len(chunkedRaw), len(body))
	if len(body) != 0x110 {
		t.Fatalf("body 应为 0x110=272 字节, 实际 %d: %q", len(body), string(body[:minInt(len(body), 60)]))
	}
	if string(body[:16]) != "ED8D50FCBB00FDC3" {
		t.Fatalf("body 内容不符: %q", string(body[:16]))
	}
	t.Log("chunked 读取 PASS")
}
