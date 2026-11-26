package main

import (
	"strings"
	"testing"
)

// 静态解析器: ZSM 载荷绝不能误判 (动态 UUID 不在静态表)
func TestDecodeStaticRejectsZSM(t *testing.T) {
	syntheticZSM := []byte("001@" + strings.Repeat("AB", 32) + "$11111111-2222-3333-4444-555555555555]dummy_lzma_payload")
	if _, _, err := decodeStaticTicket(syntheticZSM); err == nil {
		t.Errorf("ZSM 载荷被误判为静态算法!")
	}
}

// 合成静态响应: key(32B) + algoid(AES-ECB UUID) 应解析成功
func TestDecodeStaticOK(t *testing.T) {
	data := make([]byte, 0, 4+32+1+36)
	data = append(data, 0, 0, 0, 32)
	data = append(data, make([]byte, 32)...)
	data = append(data, 36)
	data = append(data, []byte(AlgoAesEcb)...)
	ci, aid, err := decodeStaticTicket(data)
	if err != nil {
		t.Fatalf("静态解析失败: %v", err)
	}
	if aid != AlgoAesEcb {
		t.Fatalf("algoid 不符: %s", aid)
	}
	if ci == nil {
		t.Fatal("cipher 为空")
	}
	// 全 9 个 UUID 都应能 newCipher
	for _, a := range []string{AlgoAesEcb, AlgoAesCbc, AlgoXTea, AlgoXTeaIv, AlgoSm4Cbc, AlgoSm4Ecb, AlgoZUC, AlgoDesCbc, AlgoDesEcb} {
		if _, err := newCipher(a); err != nil {
			t.Errorf("算法 %s 未内置: %v", a, err)
		}
	}
}
