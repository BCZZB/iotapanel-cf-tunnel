// SPDX-License-Identifier: Apache-2.0
// cloudflared 进程托管：下载（含镜像回退）、setsid 脱离启动（面板/插件重启不影响隧道）、
// PID 文件认领、掉线自动拉起（指数退避）、日志轮转与尾部读取。低占用：插件空闲仅心跳检查。
package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	logMaxBytes   = 2 << 20 // 超过 2MB 轮转
	watchInterval = 10 * time.Second
)

// installState 下载进度（原子快照，供状态轮询）。
type installState struct {
	Running bool   `json:"running"`
	Phase   string `json:"phase"` // downloading / verifying / done / error
	Bytes   int64  `json:"bytes"` // 已下载
	Total   int64  `json:"total"` // Content-Length（可能 0）
	Err     string `json:"err,omitempty"`
}

// ProcManager cloudflared 生命周期管理器。
type ProcManager struct {
	mu       sync.Mutex
	binPath  string
	logPath  string
	pidPath  string
	pid      int
	started  time.Time // 本次运行起点（认领进程时从 /proc 推算）
	autoUp   bool      // 自动拉起开关（用户主动 Stop 后关闭）
	stopFlag bool      // 用户主动停止标记（watcher 不再拉起）
	lastErr  string
	install  atomic.Pointer[installState]
	tokenFn  func() string // 取当前隧道 token
	watchCh  chan struct{}
}

func NewProcManager(dataDir string, tokenFn func() string) *ProcManager {
	return &ProcManager{
		binPath: filepath.Join(dataDir, "bin", "cloudflared"),
		logPath: filepath.Join(dataDir, "logs", "tunnel.log"),
		pidPath: filepath.Join(dataDir, "cloudflared.pid"),
		autoUp:  true,
		tokenFn: tokenFn,
		watchCh: make(chan struct{}),
	}
}

// Adopt 启动时认领存活进程：PID 文件 + /proc/exe 校验。
func (p *ProcManager) Adopt() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.adoptLocked()
	go p.watch()
}

func (p *ProcManager) adoptLocked() {
	p.pid = 0
	b, err := os.ReadFile(p.pidPath)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	if !procAlive(pid, p.binPath) {
		_ = os.Remove(p.pidPath)
		return
	}
	p.pid = pid
	p.started = procStartTime(pid)
	if p.started.IsZero() {
		p.started = time.Now()
	}
}

// procAlive 校验 pid 存活且可执行文件是我们的 cloudflared（防 PID 复用误判）。
func procAlive(pid int, binPath string) bool {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	// 被 trace/替换的可执行文件会带 " (deleted)" 后缀
	exe = strings.TrimSuffix(exe, " (deleted)")
	real1, _ := filepath.EvalSymlinks(exe)
	real2, _ := filepath.EvalSymlinks(binPath)
	return real1 != "" && real1 == real2
}

// procStartTime 从 /proc/<pid>/stat 读进程启动时间。
func procStartTime(pid int) time.Time {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return time.Time{}
	}
	s := string(b)
	// 第 22 字段 starttime（1/100 秒，自 boot）；跳过 comm（可能含空格）
	if i := strings.LastIndex(s, ")"); i > 0 && i+2 <= len(s) {
		fields := strings.Fields(s[i+2:])
		if len(fields) >= 20 {
			if t, err := strconv.ParseInt(fields[19], 10, 64); err == nil {
				return bootTime().Add(time.Duration(t) * 10 * time.Millisecond)
			}
		}
	}
	return time.Time{}
}

func bootTime() time.Time {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Now().Add(-time.Hour)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "btime ") {
			if t, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(sc.Text(), "btime ")), 10, 64); err == nil {
				return time.Unix(t, 0)
			}
		}
	}
	return time.Now().Add(-time.Hour)
}

// procRSS KB。
func procRSS(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				n, _ := strconv.Atoi(f[1])
				return n
			}
		}
	}
	return 0
}

// ---------- 生命周期 ----------

func (p *ProcManager) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pid > 0 && procAlive(p.pid, p.binPath)
}

// Start 启动 cloudflared（setsid 脱离进程组，插件退出不连坐）。
func (p *ProcManager) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pid > 0 && procAlive(p.pid, p.binPath) {
		return nil
	}
	token := p.tokenFn()
	if token == "" {
		return fmt.Errorf("尚未配置隧道，无法启动")
	}
	if _, err := os.Stat(p.binPath); err != nil {
		return fmt.Errorf("cloudflared 未安装")
	}
	if err := os.MkdirAll(filepath.Dir(p.logPath), 0o755); err != nil {
		return err
	}
	rotateIfBig(p.logPath)
	logF, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logF.Close()
	cmd := exec.Command(p.binPath, "tunnel", "--no-autoupdate",
		"--loglevel", "info", "--metrics", "127.0.0.1:0",
		"run", "--token", token)
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	p.pid = cmd.Process.Pid
	p.started = time.Now()
	p.autoUp = true
	p.stopFlag = false
	p.lastErr = ""
	_ = os.WriteFile(p.pidPath, []byte(fmt.Sprint(p.pid)), 0o644)
	// 回收僵尸（setsid 后父进程仍是本插件，直到插件退出过继给 init）
	go func() { _ = cmd.Wait() }()
	return nil
}

// Stop 用户主动停止：信号发进程组，watcher 停止拉起。
func (p *ProcManager) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopFlag = true
	p.autoUp = false
	if p.pid <= 0 {
		return nil
	}
	pid := p.pid
	p.pid = 0
	_ = os.Remove(p.pidPath)
	// setsid 后 cloudflared 自成进程组长
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	_ = syscall.Kill(pid, syscall.SIGTERM)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !procAlive(pid, p.binPath) {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	return nil
}

// Restart = Stop + Start。
func (p *ProcManager) Restart() error {
	if err := p.Stop(); err != nil {
		return err
	}
	time.Sleep(300 * time.Millisecond)
	return p.Start()
}

// watch 掉线自动拉起（指数退避封顶 5 分钟；用户 Stop 后不再拉起）。
func (p *ProcManager) watch() {
	fails := 0
	for {
		select {
		case <-p.watchCh:
			return
		case <-time.After(watchInterval):
		}
		p.mu.Lock()
		if p.stopFlag || !p.autoUp || p.tokenFn() == "" {
			fails = 0
			p.mu.Unlock()
			continue
		}
		alive := p.pid > 0 && procAlive(p.pid, p.binPath)
		if alive {
			fails = 0
			p.mu.Unlock()
			continue
		}
		p.pid = 0
		_ = os.Remove(p.pidPath)
		fails++
		if fails > 30 { // 连续失败太多：放弃自动拉起，等用户介入
			p.lastErr = "自动拉起连续失败 30 次，已暂停（查看日志排查）"
			p.autoUp = false
			p.mu.Unlock()
			continue
		}
		backoff := time.Duration(1<<min(fails, 5)) * time.Second
		if backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
		p.lastErr = fmt.Sprintf("检测到掉线，%.0f 秒后第 %d 次拉起", backoff.Seconds(), fails)
		p.mu.Unlock()
		time.Sleep(backoff)
		if err := p.Start(); err != nil {
			p.mu.Lock()
			p.lastErr = "拉起失败: " + err.Error()
			p.mu.Unlock()
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Status 进程状态快照。
func (p *ProcManager) Status() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	installed := false
	var ver string
	if fi, err := os.Stat(p.binPath); err == nil && fi.Size() > 1<<20 {
		installed = true
	}
	running := p.pid > 0 && procAlive(p.pid, p.binPath)
	if running {
		if out, err := exec.Command(p.binPath, "--version").Output(); err == nil {
			ver = strings.TrimSpace(string(out))
		}
	}
	st := map[string]any{
		"installed": installed,
		"running":   running,
		"version":   ver,
		"lastErr":   p.lastErr,
	}
	if running {
		st["pid"] = p.pid
		st["rssKb"] = procRSS(p.pid)
		start := p.started
		if start.IsZero() {
			start = time.Now()
		}
		st["uptime"] = int64(time.Since(start).Seconds())
	}
	return st
}

// TailLog 日志尾部 n 行。
func (p *ProcManager) TailLog(n int) []string {
	f, err := os.Open(p.logPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 256<<10)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return lines
}

// AppendLog 外部写一行到日志（如边缘优选应用记录）。
func (p *ProcManager) AppendLog(line string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(p.logPath), 0o755); err != nil {
		return
	}
	rotateIfBig(p.logPath)
	f, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
}

func rotateIfBig(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > logMaxBytes {
		_ = os.Rename(path, path+".1")
	}
}

// ---------- 安装 ----------

// cloudflaredDownloadURLs 候选下载地址（自定义镜像 → 直连 → 公共镜像回退）。
func (p *ProcManager) downloadURLs(mirror string) []string {
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		arch = "amd64" // 其余架构按 amd64 兜底（cloudflared 官方仅发布这两类 Linux 版）
	}
	base := "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-" + arch
	urls := []string{}
	if m := strings.TrimSpace(mirror); m != "" {
		m = strings.TrimSuffix(m, "/")
		urls = append(urls, m+"/"+base)
	}
	urls = append(urls, base, "https://ghproxy.net/"+base)
	return urls
}

// Install 下载 cloudflared（后台 goroutine，进度经 InstallState 查询）。
func (p *ProcManager) Install(mirror string) error {
	p.mu.Lock()
	pending := p.install.Load()
	if pending != nil && pending.Running {
		p.mu.Unlock()
		return fmt.Errorf("下载进行中")
	}
	p.mu.Unlock()

	p.install.Store(&installState{Running: true, Phase: "downloading"})
	go func() {
		var lastErr error
		for _, u := range p.downloadURLs(mirror) {
			if err := p.downloadTo(u); err != nil {
				lastErr = fmt.Errorf("%s: %v", u, err)
				continue
			}
			st := &installState{Running: false, Phase: "done"}
			p.install.Store(st)
			p.AppendLog(fmt.Sprintf("[cf-tunnel] cloudflared 安装完成: %s", u))
			return
		}
		p.install.Store(&installState{Running: false, Phase: "error", Err: lastErr.Error()})
	}()
	return nil
}

func (p *ProcManager) downloadTo(u string) error {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	hc := &http.Client{Timeout: 10 * time.Minute}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(p.binPath), 0o755); err != nil {
		return err
	}
	tmp := p.binPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	total := resp.ContentLength
	var got int64
	buf := make([]byte, 64<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				return werr
			}
			got += int64(n)
			if total > 0 {
				p.install.Store(&installState{Running: true, Phase: "downloading", Bytes: got, Total: total})
			} else {
				p.install.Store(&installState{Running: true, Phase: "downloading", Bytes: got})
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return rerr
		}
	}
	f.Close()
	// 校验大小（cloudflared 约 30-50MB，过小必为错误页）
	if got < 5<<20 {
		os.Remove(tmp)
		return fmt.Errorf("文件过小(%d字节)，疑似错误响应", got)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	// 校验可执行
	out, err := exec.Command(tmp, "--version").Output()
	if err != nil || !strings.Contains(string(out), "cloudflared") {
		os.Remove(tmp)
		return fmt.Errorf("--version 校验失败: %v", err)
	}
	return os.Rename(tmp, p.binPath)
}

// InstallState 下载进度快照。
func (p *ProcManager) InstallState() installState {
	if st := p.install.Load(); st != nil {
		return *st
	}
	return installState{}
}
