package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

const pinnedDNSTimeout = 1800 * time.Millisecond

// builtinPortalHostIPs 内置广东电信天翼校园网核心调度域名保底 IP，确保在 DNS 被 AC 彻底黑洞/劫持时仍可完成认证
var builtinPortalHostIPs = map[string][]string{
	"enet.10000.gd.cn": {"125.88.59.131", "61.140.12.23"},
}

// telecomFallbackDNS 广东电信及国内直连公共 DNS 竞赛池（用于旁路用户自定义的 8.8.8.8 / 127.0.0.1 等预认证失效 DNS）
var telecomFallbackDNS = []string{
	"202.96.128.86",
	"202.96.128.166",
	"202.96.134.133",
	"202.96.128.68",
	"223.5.5.5",
	"114.114.114.114",
	"119.29.29.29",
}

type dnsCacheEntry struct {
	ips     []string
	source  string
	expires time.Time
}

var (
	dnsRaceCacheMu sync.Mutex
	dnsRaceCache   = map[string]dnsCacheEntry{}
)

func clearDNSRaceCache() {
	dnsRaceCacheMu.Lock()
	dnsRaceCache = map[string]dnsCacheEntry{}
	dnsRaceCacheMu.Unlock()
}

func normDNSHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func isValidResolvedIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.IsLoopback() || ip4.IsUnspecified() || ip4.IsLinkLocalUnicast() || ip4.IsMulticast() || isFakeIP(ip4) {
		return false
	}
	return true
}

func randDNSID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err == nil {
		id := binary.BigEndian.Uint16(b[:])
		if id != 0 {
			return id
		}
	}
	return uint16(time.Now().UnixNano() & 0xFFFF)
}

// buildDNSQueryA 构造 RFC1035 标准 IPv4 A 记录 UDP 查询报文 (RD=1, QDCOUNT=1)
func buildDNSQueryA(id uint16, host string) ([]byte, error) {
	h := normDNSHost(host)
	if h == "" || len(h) > 253 {
		return nil, fmt.Errorf("无效域名: %q", host)
	}
	labels := strings.Split(h, ".")
	pkt := make([]byte, 0, 12+len(h)+6)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // Standard query, RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	pkt = append(pkt, hdr[:]...)
	for _, lb := range labels {
		if lb == "" || len(lb) > 63 {
			return nil, fmt.Errorf("无效域名标签: %q", host)
		}
		pkt = append(pkt, byte(len(lb)))
		pkt = append(pkt, lb...)
	}
	pkt = append(pkt, 0x00)       // Root label
	pkt = append(pkt, 0x00, 0x01) // QTYPE = A (1)
	pkt = append(pkt, 0x00, 0x01) // QCLASS = IN (1)
	return pkt, nil
}

// skipDNSName 跳过 DNS 报文中的域名字段（正确处理 0xC0 压缩指针及边界校验）
func skipDNSName(pkt []byte, off int) (int, error) {
	if off < 0 || off >= len(pkt) {
		return 0, errors.New("DNS 域名越界")
	}
	steps := 0
	for {
		if off >= len(pkt) {
			return 0, errors.New("DNS 域名截断")
		}
		b := pkt[off]
		if (b & 0xC0) == 0xC0 {
			if off+1 >= len(pkt) {
				return 0, errors.New("DNS 压缩指针截断")
			}
			return off + 2, nil
		}
		if (b & 0xC0) != 0 {
			return 0, errors.New("DNS 非法标签长度前缀")
		}
		if b == 0 {
			return off + 1, nil
		}
		off += 1 + int(b)
		steps++
		if steps > 128 || off > len(pkt) {
			return 0, errors.New("DNS 域名标签越界")
		}
	}
}

// parseDNSResponseA 解析 DNS UDP 响应中的有效 IPv4 A 记录（过滤 CNAME/Fake-IP/环回/广播）
func parseDNSResponseA(pkt []byte, expectedID uint16) []net.IP {
	if len(pkt) < 12 {
		return nil
	}
	if binary.BigEndian.Uint16(pkt[0:2]) != expectedID {
		return nil
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if (flags&0x8000) == 0 || (flags&0x000F) != 0 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		off, err = skipDNSName(pkt, off)
		if err != nil || off+4 > len(pkt) {
			return nil
		}
		off += 4 // QTYPE + QCLASS
	}
	var out []net.IP
	seen := map[string]bool{}
	for i := 0; i < an; i++ {
		off, err = skipDNSName(pkt, off)
		if err != nil || off+10 > len(pkt) {
			break
		}
		rtype := binary.BigEndian.Uint16(pkt[off : off+2])
		rclass := binary.BigEndian.Uint16(pkt[off+2 : off+4])
		rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		off += 10
		if off+rdlen > len(pkt) {
			break
		}
		if rtype == 1 && rclass == 1 && rdlen == 4 {
			ip := net.IPv4(pkt[off], pkt[off+1], pkt[off+2], pkt[off+3])
			if isValidResolvedIPv4(ip) {
				s := ip.String()
				if !seen[s] {
					seen[s] = true
					out = append(out, ip)
				}
			}
		}
		off += rdlen
	}
	return out
}

// querySingleDNS4 向单个 DNS 服务器发送物理网卡绑定的 UDP/53 A 记录查询（支持 ip:port 测试地址）
func querySingleDNS4(ctx context.Context, srcIP net.IP, ifIndex uint32, dnsAddr, host string) ([]net.IP, error) {
	id := randDNSID()
	pkt, err := buildDNSQueryA(id, host)
	if err != nil {
		return nil, err
	}
	target := strings.TrimSpace(dnsAddr)
	if target == "" {
		return nil, errors.New("空 DNS 地址")
	}
	if _, _, splitErr := net.SplitHostPort(target); splitErr != nil {
		target = net.JoinHostPort(target, "53")
	}
	d := &net.Dialer{Timeout: pinnedDNSTimeout}
	if srcIP != nil && srcIP.To4() != nil {
		d.LocalAddr = &net.UDPAddr{IP: srcIP.To4()}
	}
	if ifIndex > 0 {
		d.Control = func(_, _ string, rc syscall.RawConn) error {
			var sockErr error
			if cerr := rc.Control(func(fd uintptr) {
				sockErr = SetSocketUnicastIf4(fd, ifIndex)
			}); cerr != nil {
				return cerr
			}
			return sockErr
		}
	}
	conn, err := d.DialContext(ctx, "udp4", target)
	if err != nil {
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	defer conn.Close()

	dl := time.Now().Add(pinnedDNSTimeout)
	if ctxDL, ok := ctx.Deadline(); ok && ctxDL.Before(dl) {
		dl = ctxDL
	}
	_ = conn.SetDeadline(dl)
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	ips := parseDNSResponseA(buf[:n], id)
	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS(%s) 未返回有效 IPv4 A 记录", dnsAddr)
	}
	return ips, nil
}

func hasNonDefaultDNSPort(servers []string) bool {
	for _, s := range servers {
		if _, p, err := net.SplitHostPort(strings.TrimSpace(s)); err == nil && p != "" && p != "53" {
			return true
		}
	}
	return false
}

// racePinnedDNS4NoCache 并发向多个 DNS 发起 UDP 查询，任一返回合法非 Fake-IP A 记录立即胜出并取消其余请求
func racePinnedDNS4NoCache(ctx context.Context, srcIP net.IP, ifIndex uint32, servers []string, host string) ([]net.IP, string, error) {
	var cands []string
	seen := map[string]bool{}
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		cands = append(cands, s)
		if len(cands) >= 10 {
			break
		}
	}
	if len(cands) == 0 {
		return nil, "", errors.New("无可用 DNS 服务器")
	}
	raceCtx, cancel := context.WithTimeout(ctx, pinnedDNSTimeout)
	defer cancel()

	type res struct {
		ips    []net.IP
		server string
		err    error
	}
	ch := make(chan res, len(cands))
	for _, srv := range cands {
		go func(s string) {
			ips, err := querySingleDNS4(raceCtx, srcIP, ifIndex, s, host)
			ch <- res{ips: ips, server: s, err: err}
		}(srv)
	}
	var lastErr error
	for i := 0; i < len(cands); i++ {
		select {
		case r := <-ch:
			if len(r.ips) > 0 {
				cancel()
				return r.ips, r.server, nil
			}
			if r.err != nil {
				lastErr = r.err
			}
		case <-raceCtx.Done():
			if lastErr == nil {
				lastErr = raceCtx.Err()
			}
			return nil, "", lastErr
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("并发 DNS 解析超时或无合法结果 (%s)", host)
	}
	return nil, "", lastErr
}

// racePinnedDNS4 带 5 分钟 TTL 缓存的并发物理网卡 DNS 解析器
func racePinnedDNS4(ctx context.Context, srcIP net.IP, ifIndex uint32, servers []string, host string) ([]net.IP, string, error) {
	useCache := !hasNonDefaultDNSPort(servers)
	cacheKey := fmt.Sprintf("%d|%s", ifIndex, normDNSHost(host))
	now := time.Now()
	if useCache {
		dnsRaceCacheMu.Lock()
		ent, ok := dnsRaceCache[cacheKey]
		dnsRaceCacheMu.Unlock()
		if ok && now.Before(ent.expires) && len(ent.ips) > 0 {
			out := make([]net.IP, 0, len(ent.ips))
			for _, s := range ent.ips {
				if ip := net.ParseIP(s).To4(); ip != nil {
					out = append(out, ip)
				}
			}
			if len(out) > 0 {
				return out, ent.source, nil
			}
		}
	}

	ips, srv, err := racePinnedDNS4NoCache(ctx, srcIP, ifIndex, servers, host)
	if err != nil {
		return nil, "", err
	}
	if useCache {
		strs := make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				strs = append(strs, ip4.String())
			}
		}
		dnsRaceCacheMu.Lock()
		dnsRaceCache[cacheKey] = dnsCacheEntry{
			ips:     strs,
			source:  srv,
			expires: now.Add(5 * time.Minute),
		}
		dnsRaceCacheMu.Unlock()
	}
	return ips, srv, nil
}

// resolvePinnedIP4List 优先并发竞速物理网卡/DHCP/电信 DNS，全部失败时自动回退至内置核心 Portal 节点 IP
func resolvePinnedIP4List(ctx context.Context, srcIP net.IP, ifIndex uint32, dnsServers []string, host string) ([]string, string, error) {
	trimmed := strings.TrimSpace(host)
	if ip := net.ParseIP(trimmed); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return []string{ip4.String()}, "literal", nil
		}
	}
	targets := cleanPhysicalDNS(dnsServers)
	ips, srv, err := racePinnedDNS4(ctx, srcIP, ifIndex, targets, trimmed)
	if err == nil && len(ips) > 0 {
		out := make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, ip4.String())
			}
		}
		if len(out) > 0 {
			return out, "dns:" + srv, nil
		}
	}
	if fb, ok := builtinPortalHostIPs[normDNSHost(trimmed)]; ok && len(fb) > 0 {
		cp := make([]string, len(fb))
		copy(cp, fb)
		return cp, "builtin-fallback", nil
	}
	if err == nil {
		err = fmt.Errorf("DNS 无可用 IPv4 地址 (%s)", trimmed)
	}
	return nil, "", err
}
