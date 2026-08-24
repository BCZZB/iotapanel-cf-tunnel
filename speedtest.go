// SPDX-License-Identifier: Apache-2.0
// 优选 IP 测速（参考 XIU2/CloudflareSpeedTest 思路，纯标准库实现）：
//   - 延迟：TCP 拨测 Cloudflare 全 IP 段随机采样（443=访客入口 / 7844=隧道边缘），高并发
//   - 速度：对延迟最优的前 N 个 IP 走 https://speed.cloudflare.com/__down 直连测速（拨号覆写）
//   - 彩蛋：每个优选 IP 附带 PoP 机房代号（/cdn-cgi/trace）
//
// 低占用：仅按需运行，跑完即释放全部资源；无后台常驻轮询。
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// cfCIDRs Cloudflare 官方公布的 IPv4 段（cloudflare.com/ips-v4），运行时经 netip 解析，
// 绝不手算整数（手算易错，曾导致采样到非 CF 地址）。
var cfCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

type ipRange struct{ start, end uint32 }

func mustParseCIDR(cidr string) ipRange {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic("解析 CF IP 段失败: " + cidr + ": " + err.Error())
	}
	a := p.Masked().Addr().As4()
	start := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	// 结束 = 网络地址 + 主机位全 1（如 /20 → +4095）
	end := start | (^uint32(0) >> p.Bits())
	return ipRange{start, end}
}

// cfRanges 解析后的区间表（进程启动时构建一次）。
var cfRanges = func() []ipRange {
	rs := make([]ipRange, 0, len(cfCIDRs))
	for _, c := range cfCIDRs {
		rs = append(rs, mustParseCIDR(c))
	}
	return rs
}()

func ipStr(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", v>>24, (v>>16)&0xff, (v>>8)&0xff, v&0xff)
}

// sampleIPs 按段容量加权随机采样（避免小段被淹没）。
func sampleIPs(n int) []string {
	total := uint64(0)
	weights := make([]uint64, len(cfRanges))
	for i, r := range cfRanges {
		w := uint64(r.end-r.start) + 1
		weights[i] = w
		total += w
	}
	seen := map[uint32]bool{}
	out := make([]string, 0, n)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for len(out) < n {
		x := rng.Uint64() % total
		var idx int
		for i, w := range weights {
			if x < w {
				idx = i
				break
			}
			x -= w
		}
		r := cfRanges[idx]
		ip := r.start + uint32(rng.Int63n(int64(r.end-r.start)+1))
		if seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ipStr(ip))
	}
	return out
}

// IPResult 单 IP 测速结果。
type IPResult struct {
	IP        string  `json:"ip"`
	LatencyMs float64 `json:"latencyMs"` // 平均延迟（失败尝试不计入）
	Loss      int     `json:"loss"`      // 失败次数（2=全挂）
	SpeedMbps float64 `json:"speedMbps,omitempty"`
	Colo      string  `json:"colo,omitempty"` // PoP 机房代号（如 SVO/MOW）
}

// SpeedState 测速任务状态（轮询）。
type SpeedState struct {
	Running   bool       `json:"running"`
	Phase     string     `json:"phase"` // latency / speed / done / error / cancelled
	Mode      string     `json:"mode"`  // visitor(443) / edge(7844)
	Tested    int        `json:"tested"`
	Total     int        `json:"total"`
	Results   []IPResult `json:"results,omitempty"` // 已按延迟排序
	Error     string     `json:"error,omitempty"`
	StartedAt time.Time  `json:"startedAt"`
	EndedAt   time.Time  `json:"endedAt,omitempty"`
}

// SpeedTester 测速器。
type SpeedTester struct {
	mu      sync.Mutex
	state   SpeedState
	cancel  context.CancelFunc
	results []IPResult
}

func NewSpeedTester() *SpeedTester {
	return &SpeedTester{}
}

// State 快照。
func (t *SpeedTester) State() SpeedState {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state
	if len(t.results) > 0 {
		rs := make([]IPResult, len(t.results))
		copy(rs, t.results)
		st.Results = rs
	}
	return st
}

// Stop 取消当前任务。
func (t *SpeedTester) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		t.cancel()
	}
}

// Start 启动测速。mode: visitor=443 / edge=7844；count 采样数；speedCount>0 时对前 N 名测下载速度。
func (t *SpeedTester) Start(mode string, count, speedCount int, speedBytes int64) error {
	t.mu.Lock()
	if t.state.Running {
		t.mu.Unlock()
		return fmt.Errorf("测速进行中")
	}
	if count < 10 {
		count = 10
	}
	if count > 400 {
		count = 400
	}
	port := 443
	if mode == "edge" {
		port = 7844
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.state = SpeedState{
		Running:   true,
		Phase:     "latency",
		Mode:      mode,
		Total:     count,
		StartedAt: time.Now(),
	}
	t.results = nil
	t.state.Tested = 0
	t.mu.Unlock()

	go t.run(ctx, mode, port, count, speedCount, speedBytes)
	return nil
}

func (t *SpeedTester) setPhase(ph string) {
	t.mu.Lock()
	t.state.Phase = ph
	t.mu.Unlock()
}

func (t *SpeedTester) finish(err error) {
	t.mu.Lock()
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.state.Running = false
	t.state.EndedAt = time.Now()
	if err != nil {
		t.state.Phase = "error"
		t.state.Error = err.Error()
	} else {
		t.state.Phase = "done"
	}
	t.mu.Unlock()
}

func (t *SpeedTester) run(ctx context.Context, mode string, port, count, speedCount int, speedBytes int64) {
	ips := sampleIPs(count)

	// ---------- 阶段 1：TCP 延迟 ----------
	type latRes struct {
		r IPResult
	}
	ch := make(chan latRes, 64)
	work := make(chan string)
	// 生产者
	go func() {
		for _, ip := range ips {
			select {
			case work <- ip:
			case <-ctx.Done():
				close(work)
				return
			}
		}
		close(work)
	}()
	var wg sync.WaitGroup
	concurrency := 64
	if port == 7844 {
		concurrency = 32 // 隧道边缘端口更谨慎
	}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}
				r := IPResult{IP: ip}
				ok := 0
				var sum float64
				for a := 0; a < 2; a++ { // 每 IP 拨 2 次取均值
					select {
					case <-ctx.Done():
					default:
					}
					d, err := tcpPing(ip, port, time.Second)
					if err != nil {
						r.Loss++
						continue
					}
					sum += d.Seconds() * 1000
					ok++
				}
				if ok > 0 {
					r.LatencyMs = round2(sum / float64(ok))
				} else {
					r.LatencyMs = -1
				}
				ch <- latRes{r}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	n := 0
	for res := range ch {
		n++
		t.mu.Lock()
		t.state.Tested = n
		if res.r.LatencyMs > 0 {
			t.results = append(t.results, res.r)
		}
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			t.finish(fmt.Errorf("已取消"))
			return
		default:
		}
	}
	if ctx.Err() != nil {
		t.finish(fmt.Errorf("已取消"))
		return
	}
	t.mu.Lock()
	sort.Slice(t.results, func(i, j int) bool { return t.results[i].LatencyMs < t.results[j].LatencyMs })
	// 只保留延迟最优的前 60 名展示
	if len(t.results) > 60 {
		t.results = t.results[:60]
	}
	t.mu.Unlock()
	if len(t.results) == 0 {
		t.finish(fmt.Errorf("所有采样 IP 均不可达（检查服务器出网或代理）"))
		return
	}

	// ---------- 阶段 2：下载速度 + PoP（仅 443 模式；7844 不承载 HTTP） ----------
	if mode == "visitor" && speedCount > 0 {
		t.setPhase("speed")
		if speedBytes <= 0 {
			speedBytes = 5_000_000 // 5MB
		}
		t.mu.Lock()
		top := make([]IPResult, min(speedCount, len(t.results)))
		copy(top, t.results)
		t.mu.Unlock()
		for i := range top {
			select {
			case <-ctx.Done():
				t.finish(fmt.Errorf("已取消"))
				return
			default:
			}
			mbps, colo, err := speedTest(ctx, top[i].IP, speedBytes)
			if err == nil {
				top[i].SpeedMbps = mbps
				top[i].Colo = colo
			}
			// 回写结果
			t.mu.Lock()
			for j := range t.results {
				if t.results[j].IP == top[i].IP {
					t.results[j].SpeedMbps = top[i].SpeedMbps
					t.results[j].Colo = top[i].Colo
					break
				}
			}
			t.mu.Unlock()
		}
	}
	t.finish(nil)
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

// tcpPing TCP 拨测延迟。
func tcpPing(ip string, port int, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

// speedTest 对指定 IP 直连测下载速度（拨号覆写：SNI/Host=speed.cloudflare.com）。
// 同时取 /cdn-cgi/trace 拿 PoP 机房代号。
func speedTest(ctx context.Context, ip string, bytes int64) (mbps float64, colo string, err error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 忽略 addr 中的域名，直连被测 IP
			_, port, _ := net.SplitHostPort(addr)
			if port == "" {
				port = "443"
			}
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:          2,
		DisableCompression:    true,
	}
	hc := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	defer hc.CloseIdleConnections()

	// 速度：__down
	req, _ := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", bytes), nil)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	start := time.Now()
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil && n == 0 {
		return 0, "", err
	}
	secs := time.Since(start).Seconds()
	if secs <= 0 {
		return 0, "", fmt.Errorf("测速时间异常")
	}
	mbps = round2(float64(n) * 8 / secs / 1e6)

	// PoP：/cdn-cgi/trace（www.cloudflare.com 走同一边缘）
	req2, _ := http.NewRequestWithContext(ctx, "GET",
		"https://www.cloudflare.com/cdn-cgi/trace", nil)
	if resp2, err := hc.Do(req2); err == nil {
		b, _ := io.ReadAll(io.LimitReader(resp2.Body, 2048))
		resp2.Body.Close()
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "colo=") {
				colo = strings.TrimSpace(strings.TrimPrefix(line, "colo="))
			}
		}
	}
	return mbps, colo, nil
}
