// SPDX-License-Identifier: Apache-2.0
// 管理 API：设置 / Cloudflare 隧道与映射 / cloudflared 进程 / 优选 IP /
// web-manager 联动（经面板 port-map.json 自动发现端口）。
// 安全模型与 web-manager 一致：安全响应头 + 限流 + CSRF（网关注入的插件标记头）。
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

const maxBodyBytes = 1 << 20

// ---------- 限流（与 web-manager 同款令牌桶） ----------

type bucket struct {
	tokens float64
	last   time.Time
}

type ipLimiter struct {
	mu sync.Mutex
	m  map[string]*bucket
}

func newIPLimiter() *ipLimiter { return &ipLimiter{m: map[string]*bucket{}} }

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.m) > 4096 {
		for k, b := range l.m {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.m, k)
			}
		}
	}
	b, ok := l.m[ip]
	if !ok {
		b = &bucket{tokens: 30, last: now}
		l.m[ip] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * 5
	if b.tokens > 30 {
		b.tokens = 30
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func remoteIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

// ---------- App ----------

type App struct {
	pluginName string
	home       string
	etcDir     string
	dataDir    string
	store      *Store
	proc       *ProcManager
	speed      *SpeedTester
	limiter    *ipLimiter
	startedAt  time.Time

	tunnelCacheMu sync.Mutex
	tunnelCacheAt time.Time
	tunnelCache   map[string]any
}

func NewApp(home, pluginName string) (*App, error) {
	etcDir := filepath.Join(home, "etc", "cf-tunnel")
	dataDir := filepath.Join(home, "data", "cf-tunnel")
	for _, d := range []string{etcDir, dataDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	store, err := LoadStore(etcDir)
	if err != nil {
		return nil, err
	}
	a := &App{
		pluginName: pluginName,
		home:       home,
		etcDir:     etcDir,
		dataDir:    dataDir,
		store:      store,
		limiter:    newIPLimiter(),
		startedAt:  time.Now(),
		speed:      NewSpeedTester(),
	}
	a.proc = NewProcManager(dataDir, func() string {
		if t := a.store.Cfg().Tunnel; t != nil {
			return t.Token
		}
		return ""
	})
	a.proc.Adopt() // 认领插件重启前存活的 cloudflared
	return a, nil
}

// ---------- 路由 ----------

func (a *App) adminMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleIndex)
	mux.HandleFunc("GET /api/status", a.handleStatus)

	mux.HandleFunc("GET /api/settings", a.handleGetSettings)
	mux.HandleFunc("PUT /api/settings", a.handlePutSettings)
	mux.HandleFunc("POST /api/cf/verify", a.handleCFVerify)
	mux.HandleFunc("GET /api/cf/zones", a.handleCFZones)

	mux.HandleFunc("GET /api/cf/tunnels", a.handleListTunnels)
	mux.HandleFunc("POST /api/cf/tunnel", a.handleCreateTunnel)
	mux.HandleFunc("POST /api/cf/tunnel/import", a.handleImportTunnel)
	mux.HandleFunc("DELETE /api/cf/tunnel", a.handleDeleteTunnel)

	mux.HandleFunc("GET /api/mappings", a.handleListMappings)
	mux.HandleFunc("POST /api/mappings", a.handleAddMapping)
	mux.HandleFunc("DELETE /api/mappings/{hostname}", a.handleDeleteMapping)

	mux.HandleFunc("GET /api/wm/sites", a.handleWMSites)
	mux.HandleFunc("GET /api/wm/config", a.handleWMConfig)

	mux.HandleFunc("GET /api/connector", a.handleConnector)
	mux.HandleFunc("POST /api/connector/install", a.handleInstall)
	mux.HandleFunc("POST /api/connector/start", a.handleConnStart)
	mux.HandleFunc("POST /api/connector/stop", a.handleConnStop)
	mux.HandleFunc("POST /api/connector/restart", a.handleConnRestart)
	mux.HandleFunc("GET /api/connector/log", a.handleConnLog)

	mux.HandleFunc("GET /api/speed", a.handleSpeedGet)
	mux.HandleFunc("POST /api/speed", a.handleSpeedStart)
	mux.HandleFunc("POST /api/speed/stop", a.handleSpeedStop)
	mux.HandleFunc("POST /api/speed/apply-edge", a.handleApplyEdge)
	mux.HandleFunc("POST /api/speed/remove-edge", a.handleRemoveEdge)
	mux.HandleFunc("GET /api/speed/hosts-export", a.handleHostsExport)

	return a.secure(mux)
}

func (a *App) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		ip := remoteIP(r.RemoteAddr)
		if !a.limiter.allow(ip) {
			writeErr(w, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			if v := r.Header.Get("X-Panel-Plugin"); v == "" || v != a.pluginName {
				origin := r.Header.Get("Origin")
				host := r.Host
				if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
					host = fh
				}
				if origin != "" && host != "" && !sameOrigin(origin, host) {
					writeErr(w, http.StatusForbidden, "禁止：跨站请求校验失败")
					return
				}
				if origin != "" && sameOrigin(origin, host) {
					break
				}
				if ip != "127.0.0.1" && ip != "::1" {
					writeErr(w, http.StatusForbidden, "禁止：跨站请求校验失败")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	o := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	return o == host
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, v)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	sub, _ := fs.Sub(webFS, "web")
	f, err := sub.Open("index.html")
	if err != nil {
		writeErr(w, 500, "UI 资源缺失")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.Copy(w, f)
}

// ---------- 状态 ----------

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Cfg()
	st := map[string]any{
		"ok":              true,
		"uptime":          int64(time.Since(a.startedAt).Seconds()),
		"tokenConfigured": cfg.APIToken != "",
		"account":         nil,
		"tunnel":          nil,
		"mappings":        len(cfg.Mappings),
		"edgeOpt":         a.edgeOptView(),
		"connector":       a.proc.Status(),
		"speed":           a.speed.State(),
	}
	if cfg.AccountID != "" {
		st["account"] = map[string]string{"id": cfg.AccountID, "name": cfg.AccountName}
	}
	if cfg.Tunnel != nil {
		st["tunnel"] = map[string]string{"id": cfg.Tunnel.ID, "name": cfg.Tunnel.Name}
		st["tunnelStatus"] = a.cachedTunnelStatus(cfg)
	}
	st["wm"] = a.wmStatus()
	writeJSON(w, st)
}

// edgeOptView 优选边缘状态：store 记录 + /etc/hosts 实况合并。
func (a *App) edgeOptView() map[string]any {
	cfg := a.store.Cfg()
	live := hostsEdgeIPs()
	v := map[string]any{"applied": len(live) > 0, "ips": live}
	if cfg.EdgeOpt != nil {
		v["appliedAt"] = cfg.EdgeOpt.AppliedAt
		v["latency"] = cfg.EdgeOpt.Latency
	}
	return v
}

// cachedTunnelStatus CF 侧隧道状态（20s 缓存，避免高频轮询打 API）。
func (a *App) cachedTunnelStatus(cfg Config) map[string]any {
	a.tunnelCacheMu.Lock()
	defer a.tunnelCacheMu.Unlock()
	if a.tunnelCache != nil && time.Since(a.tunnelCacheAt) < 20*time.Second {
		return a.tunnelCache
	}
	out := map[string]any{}
	if cfg.APIToken != "" && cfg.AccountID != "" && cfg.Tunnel != nil {
		c := newCFClient(cfg.APIToken)
		if t, err := c.GetTunnel(cfg.AccountID, cfg.Tunnel.ID); err == nil {
			colos := []string{}
			active := 0
			for _, cn := range t.Connections {
				if !cn.IsPendingReconnect {
					active++
					if cn.ColoName != "" {
						colos = append(colos, cn.ColoName)
					}
				}
			}
			out["status"] = t.Status
			out["connections"] = active
			out["colos"] = colos
		} else {
			out["error"] = err.Error()
		}
	}
	a.tunnelCache = out
	a.tunnelCacheAt = time.Now()
	return out
}

// ---------- 设置 ----------

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Cfg()
	writeJSON(w, map[string]any{
		"ok":        true,
		"mirror":    cfg.Mirror,
		"wmPort":    cfg.WMOverridePort,
		"hasToken":  cfg.APIToken != "",
		"tokenTail": tokenTail(cfg.APIToken),
	})
}

func tokenTail(t string) string {
	if len(t) <= 8 {
		return ""
	}
	return "…" + t[len(t)-6:]
}

func (a *App) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		APIToken       string `json:"apiToken"`
		AccountID      string `json:"accountId"`
		AccountName    string `json:"accountName"`
		Mirror         string `json:"mirror"`
		WMOverridePort int    `json:"wmPort"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, "请求体格式错误")
		return
	}
	err := a.store.Update(func(c *Config) {
		if req.APIToken != "" && req.APIToken != "__keep__" {
			c.APIToken = req.APIToken
		}
		if req.AccountID != "" {
			c.AccountID = req.AccountID
			c.AccountName = req.AccountName
		}
		c.Mirror = strings.TrimSpace(req.Mirror)
		c.WMOverridePort = req.WMOverridePort
	})
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// handleCFVerify 校验 Token 并返回账号+Zone 列表（不落盘，保存走 PUT /api/settings）。
func (a *App) handleCFVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, "请求体格式错误")
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		token = a.store.Cfg().APIToken
	}
	if token == "" {
		writeErr(w, 400, "请先填写 API Token")
		return
	}
	c := newCFClient(token)
	if err := c.VerifyToken(); err != nil {
		writeErr(w, 400, "Token 无效: "+err.Error())
		return
	}
	accounts, zones, err := c.AccountsZones()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	az := make([]map[string]string, 0, len(accounts))
	for _, x := range accounts {
		az = append(az, map[string]string{"id": x.ID, "name": x.Name})
	}
	zs := make([]map[string]string, 0, len(zones))
	for _, z := range zones {
		zs = append(zs, map[string]string{"id": z.ID, "name": z.Name})
	}
	writeJSON(w, map[string]any{"ok": true, "accounts": az, "zones": zs})
}

func (a *App) handleCFZones(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Cfg()
	if cfg.APIToken == "" {
		writeErr(w, 400, "未配置 API Token")
		return
	}
	c := newCFClient(cfg.APIToken)
	_, zones, err := c.AccountsZones()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	zs := make([]map[string]string, 0, len(zones))
	for _, z := range zones {
		zs = append(zs, map[string]string{"id": z.ID, "name": z.Name})
	}
	writeJSON(w, map[string]any{"ok": true, "zones": zs})
}

// ---------- 隧道 ----------

func (a *App) cfClient() (*cfClient, error) {
	cfg := a.store.Cfg()
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("未配置 Cloudflare API Token")
	}
	if cfg.AccountID == "" {
		return nil, fmt.Errorf("未选择 Cloudflare 账号")
	}
	return newCFClient(cfg.APIToken), nil
}

func (a *App) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	c, err := a.cfClient()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfg := a.store.Cfg()
	ts, err := c.ListTunnels(cfg.AccountID)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	out := []map[string]any{}
	for _, t := range ts {
		active := 0
		for _, cn := range t.Connections {
			if !cn.IsPendingReconnect {
				active++
			}
		}
		out = append(out, map[string]any{
			"id": t.ID, "name": t.Name, "status": t.Status, "connections": active,
			"current": cfg.Tunnel != nil && cfg.Tunnel.ID == t.ID,
		})
	}
	writeJSON(w, map[string]any{"ok": true, "tunnels": out})
}

func (a *App) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, "请求体格式错误")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "iotapanel-tunnel"
	}
	c, err := a.cfClient()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	t, err := c.CreateTunnel(a.store.Cfg().AccountID, name)
	if err != nil {
		writeErr(w, 400, "创建隧道失败: "+err.Error())
		return
	}
	// 初始化空 ingress（仅兜底 404），保证 configurations 端点就绪
	_ = c.PutConfig(a.store.Cfg().AccountID, t.ID, &cfConfig{Ingress: []cfIngressRule{{Service: "http_status:404"}}})

	err = a.store.Update(func(cfg *Config) {
		cfg.Tunnel = &TunnelInfo{ID: t.ID, Name: t.Name, Token: t.Token, CreatedAt: time.Now()}
	})
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	log.Printf("[cf-tunnel] 已创建隧道 %s(%s)", name, t.ID)
	// 已装 cloudflared 则直接拉起（全自动）
	if _, err := os.Stat(a.proc.binPath); err == nil {
		if err := a.proc.Start(); err != nil {
			writeJSON(w, map[string]any{"ok": true, "id": t.ID, "name": t.Name, "started": false, "startErr": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true, "id": t.ID, "name": t.Name, "started": true})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "id": t.ID, "name": t.Name, "started": false, "needInstall": true})
}

// handleImportTunnel 导入面板外建的隧道：取 token + 读现有 ingress 为映射。
func (a *App) handleImportTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TunnelID string `json:"tunnelId"`
	}
	if err := readJSON(r, &req); err != nil || req.TunnelID == "" {
		writeErr(w, 400, "缺少 tunnelId")
		return
	}
	c, err := a.cfClient()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfg0 := a.store.Cfg()
	token, err := c.TunnelToken(cfg0.AccountID, req.TunnelID)
	if err != nil {
		writeErr(w, 400, "获取隧道 Token 失败: "+err.Error())
		return
	}
	t, err := c.GetTunnel(cfg0.AccountID, req.TunnelID)
	if err != nil {
		writeErr(w, 400, "读取隧道失败: "+err.Error())
		return
	}
	var mappings []Mapping
	if conf, err := c.GetConfig(cfg0.AccountID, req.TunnelID); err == nil {
		for _, rule := range conf.Ingress {
			if rule.Hostname != "" && rule.Service != "http_status:404" {
				mappings = append(mappings, Mapping{Hostname: rule.Hostname, Service: rule.Service})
			}
		}
	}
	err = a.store.Update(func(cfg *Config) {
		cfg.Tunnel = &TunnelInfo{ID: req.TunnelID, Name: t.Name, Token: token, CreatedAt: time.Now()}
		if len(mappings) > 0 {
			cfg.Mappings = mappings
		}
	})
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	log.Printf("[cf-tunnel] 已导入隧道 %s(%s)，映射 %d 条", t.Name, req.TunnelID, len(mappings))
	if _, err := os.Stat(a.proc.binPath); err == nil {
		_ = a.proc.Start()
	}
	writeJSON(w, map[string]any{"ok": true, "mappings": len(mappings)})
}

func (a *App) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PurgeDNS bool `json:"purgeDns"`
	}
	_ = readJSON(r, &req)
	cfg := a.store.Cfg()
	if cfg.Tunnel == nil {
		writeErr(w, 400, "当前没有管理的隧道")
		return
	}
	c, err := a.cfClient()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var errs []string
	if req.PurgeDNS {
		for _, m := range cfg.Mappings {
			if m.ZoneID == "" {
				continue
			}
			if err := c.DeleteDNS(m.ZoneID, m.Hostname); err != nil {
				errs = append(errs, m.Hostname+": "+err.Error())
			}
		}
	}
	_ = a.proc.Stop()
	if err := c.DeleteTunnel(cfg.AccountID, cfg.Tunnel.ID, true); err != nil {
		errs = append(errs, "删除隧道: "+err.Error())
	}
	_ = a.store.Update(func(c2 *Config) {
		c2.Tunnel = nil
		c2.Mappings = nil
	})
	a.tunnelCacheMu.Lock()
	a.tunnelCache = nil
	a.tunnelCacheMu.Unlock()
	if len(errs) > 0 {
		writeErr(w, 500, "部分操作失败: "+strings.Join(errs, "; "))
		return
	}
	log.Printf("[cf-tunnel] 已删除隧道 %s", cfg.Tunnel.ID)
	writeJSON(w, map[string]any{"ok": true})
}

// ---------- 映射 ----------

func (a *App) handleListMappings(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Cfg()
	ms := make([]Mapping, 0, len(cfg.Mappings))
	ms = append(ms, cfg.Mappings...)
	writeJSON(w, map[string]any{"ok": true, "mappings": ms})
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 || !strings.Contains(h, ".") ||
		strings.ContainsAny(h, "/\\:?# ") || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	return true
}

func validService(s string) bool {
	for _, p := range []string{"http://", "https://", "tcp://", "ssh://", "rdp://", "unix://", "smb://", "bastion://", "caa://"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// findZone 匹配 hostname 所属 Zone（最长后缀优先）。
func findZone(zones []cfZone, hostname string) *cfZone {
	var best *cfZone
	for i := range zones {
		z := &zones[i]
		if hostname == z.Name || strings.HasSuffix(hostname, "."+z.Name) {
			if best == nil || len(z.Name) > len(best.Name) {
				best = z
			}
		}
	}
	return best
}

func (a *App) handleAddMapping(w http.ResponseWriter, r *http.Request) {
	var req Mapping
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, "请求体格式错误")
		return
	}
	req.Hostname = strings.ToLower(strings.TrimSpace(req.Hostname))
	req.Service = strings.TrimSpace(req.Service)
	if !validHostname(req.Hostname) {
		writeErr(w, 400, "公网域名格式不正确（需完整域名，如 app.example.com）")
		return
	}
	if !validService(req.Service) {
		writeErr(w, 400, "本地服务地址需以 http:// 或 https:// 等开头")
		return
	}
	cfg := a.store.Cfg()
	if cfg.Tunnel == nil {
		writeErr(w, 400, "请先创建或导入隧道")
		return
	}
	c, err := a.cfClient()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 解析 Zone
	_, zones, err := c.AccountsZones()
	if err != nil {
		writeErr(w, 400, "读取 Zone 列表失败: "+err.Error())
		return
	}
	z := findZone(zones, req.Hostname)
	if z == nil {
		writeErr(w, 400, fmt.Sprintf("%s 不在 Cloudflare 托管的域名内（需先把域名 DNS 托管到 Cloudflare）", req.Hostname))
		return
	}
	req.ZoneID = z.ID
	req.ZoneName = z.Name
	newList := make([]Mapping, 0, len(cfg.Mappings)+1)
	replaced := false
	for _, m := range cfg.Mappings {
		if m.Hostname == req.Hostname {
			newList = append(newList, req)
			replaced = true
		} else {
			newList = append(newList, m)
		}
	}
	if !replaced {
		newList = append(newList, req)
	}
	// 写 ingress（远程托管配置热生效，无需重启 cloudflared）
	ingress := make([]cfIngressRule, 0, len(newList)+1)
	for _, m := range newList {
		ingress = append(ingress, cfIngressRule{Hostname: m.Hostname, Service: m.Service})
	}
	ingress = append(ingress, cfIngressRule{Service: "http_status:404"})
	if err := c.PutConfig(cfg.AccountID, cfg.Tunnel.ID, &cfConfig{Ingress: ingress}); err != nil {
		writeErr(w, 400, "写入隧道配置失败: "+err.Error())
		return
	}
	// DNS CNAME
	if err := c.UpsertTunnelCNAME(z.ID, req.Hostname, cfg.Tunnel.ID); err != nil {
		writeErr(w, 400, "DNS 记录写入失败: "+err.Error())
		return
	}
	err = a.store.Update(func(c2 *Config) {
		c2.Mappings = newList
	})
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	log.Printf("[cf-tunnel] 映射 %s → %s (zone %s)", req.Hostname, req.Service, z.Name)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleDeleteMapping(w http.ResponseWriter, r *http.Request) {
	hostname := strings.ToLower(r.PathValue("hostname"))
	cfg := a.store.Cfg()
	if cfg.Tunnel == nil {
		writeErr(w, 400, "当前没有管理的隧道")
		return
	}
	found := false
	newList := make([]Mapping, 0, len(cfg.Mappings))
	for _, m := range cfg.Mappings {
		if m.Hostname == hostname {
			found = true
			continue
		}
		newList = append(newList, m)
	}
	if !found {
		writeErr(w, 404, "映射不存在")
		return
	}
	c, err := a.cfClient()
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ingress := make([]cfIngressRule, 0, len(newList)+1)
	for _, m := range newList {
		ingress = append(ingress, cfIngressRule{Hostname: m.Hostname, Service: m.Service})
	}
	ingress = append(ingress, cfIngressRule{Service: "http_status:404"})
	if err := c.PutConfig(cfg.AccountID, cfg.Tunnel.ID, &cfConfig{Ingress: ingress}); err != nil {
		writeErr(w, 400, "更新隧道配置失败: "+err.Error())
		return
	}
	for _, m := range cfg.Mappings {
		if m.Hostname == hostname && m.ZoneID != "" {
			if err := c.DeleteDNS(m.ZoneID, hostname); err != nil {
				log.Printf("[cf-tunnel] 清理 DNS %s 失败: %v", hostname, err)
			}
			break
		}
	}
	_ = a.store.Update(func(c2 *Config) {
		c2.Mappings = newList
	})
	writeJSON(w, map[string]any{"ok": true})
}

// ---------- web-manager 联动 ----------

type portMapEntry struct {
	Port      int       `json:"port"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

// wmPort 发现 web-manager 管理端口：配置覆盖 > 面板 port-map.json > 默认 19000。
func (a *App) wmPort() (int, string) {
	if p := a.store.Cfg().WMOverridePort; p > 0 {
		return p, "override"
	}
	b, err := os.ReadFile(filepath.Join(a.home, "etc", "port-map.json"))
	if err == nil {
		var m map[string]portMapEntry
		if json.Unmarshal(b, &m) == nil {
			if e, ok := m["web-manager"]; ok && e.Port > 0 {
				return e.Port, "auto"
			}
		}
	}
	return 19000, "default"
}

func (a *App) wmCall(path string) ([]byte, error) {
	port, _ := a.wmPort()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Panel-Plugin", "web-manager")
	hc := &http.Client{Timeout: 5 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("web-manager 不可达（端口 %d）: %v", port, err)
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func (a *App) handleWMSites(w http.ResponseWriter, r *http.Request) {
	b, err := a.wmCall("/api/sites")
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	var j struct {
		OK    bool `json:"ok"`
		Sites []struct {
			ID      string   `json:"id"`
			Name    string   `json:"name"`
			Domains []string `json:"domains"`
			Enabled bool     `json:"enabled"`
		} `json:"sites"`
	}
	if err := json.Unmarshal(b, &j); err != nil || !j.OK {
		writeErr(w, 502, "web-manager 响应异常")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "sites": j.Sites})
}

func (a *App) handleWMConfig(w http.ResponseWriter, r *http.Request) {
	b, err := a.wmCall("/api/config")
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	// web-manager 返回 {config:{httpPort,...}}，兼容两种格式
	var j struct {
		OK       bool `json:"ok"`
		HTTPPort int  `json:"httpPort"`
		Config   struct {
			HTTPPort int `json:"httpPort"`
		} `json:"config"`
	}
	if err := json.Unmarshal(b, &j); err != nil || !j.OK {
		writeErr(w, 502, "web-manager 响应异常")
		return
	}
	httpPort := j.HTTPPort
	if httpPort == 0 && j.Config.HTTPPort > 0 {
		httpPort = j.Config.HTTPPort
	}
	port, src := a.wmPort()
	writeJSON(w, map[string]any{"ok": true, "httpPort": httpPort, "port": port, "source": src})
}

func (a *App) wmStatus() map[string]any {
	port, src := a.wmPort()
	_, err := a.wmCall("/api/status")
	return map[string]any{"port": port, "source": src, "reachable": err == nil}
}

// ---------- 连接器 ----------

func (a *App) handleConnector(w http.ResponseWriter, r *http.Request) {
	st := a.proc.Status()
	st["install"] = a.proc.InstallState()
	writeJSON(w, map[string]any{"ok": true, "connector": st})
}

func (a *App) handleInstall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mirror string `json:"mirror"`
	}
	_ = readJSON(r, &req)
	mirror := strings.TrimSpace(req.Mirror)
	if mirror == "" {
		mirror = a.store.Cfg().Mirror
	}
	if err := a.proc.Install(mirror); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleConnStart(w http.ResponseWriter, r *http.Request) {
	if err := a.proc.Start(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleConnStop(w http.ResponseWriter, r *http.Request) {
	if err := a.proc.Stop(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleConnRestart(w http.ResponseWriter, r *http.Request) {
	if err := a.proc.Restart(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleConnLog(w http.ResponseWriter, r *http.Request) {
	n := 200
	writeJSON(w, map[string]any{"ok": true, "lines": a.proc.TailLog(n)})
}

// ---------- 优选 IP ----------

func (a *App) handleSpeedGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.speed.State())
}

func (a *App) handleSpeedStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode       string `json:"mode"`       // visitor / edge
		Count      int    `json:"count"`      // 采样数
		SpeedCount int    `json:"speedCount"` // 前 N 名测下载速度
		SpeedBytes int64  `json:"speedBytes"` // 单次测速字节数
	}
	_ = readJSON(r, &req)
	if req.Mode != "edge" {
		req.Mode = "visitor"
	}
	if req.Count <= 0 {
		req.Count = 128
	}
	if req.SpeedCount < 0 {
		req.SpeedCount = 0
	}
	if req.SpeedCount == 0 && req.Mode == "visitor" {
		req.SpeedCount = 10
	}
	if req.SpeedBytes <= 0 {
		req.SpeedBytes = 5_000_000
	}
	if err := a.speed.Start(req.Mode, req.Count, req.SpeedCount, req.SpeedBytes); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleSpeedStop(w http.ResponseWriter, r *http.Request) {
	a.speed.Stop()
	writeJSON(w, map[string]any{"ok": true})
}

// handleApplyEdge 把优选 IP 写入 /etc/hosts（region1/region2.v2.argotunnel.com）。
func (a *App) handleApplyEdge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs []string `json:"ips"`
	}
	_ = readJSON(r, &req)
	ips := req.IPs
	if len(ips) == 0 { // 未指定则取当前测速结果前 2
		st := a.speed.State()
		for i, res := range st.Results {
			if i >= 2 {
				break
			}
			ips = append(ips, res.IP)
		}
	}
	if len(ips) == 0 {
		writeErr(w, 400, "没有可用的优选 IP，请先测速")
		return
	}
	if err := applyEdgeHosts(ips, a.etcDir); err != nil {
		writeErr(w, 500, "写入 /etc/hosts 失败: "+err.Error())
		return
	}
	lat := map[string]float64{}
	for _, res := range a.speed.State().Results {
		lat[res.IP] = res.LatencyMs
	}
	_ = a.store.Update(func(c *Config) {
		c.EdgeOpt = &EdgeOpt{IPs: ips, Applied: true, AppliedAt: time.Now(), Latency: lat}
	})
	a.proc.AppendLog(fmt.Sprintf("[cf-tunnel] 隧道边缘优选已应用: %v", ips))
	// 重启使连接立即走新 IP（不重启也会在重连时生效）
	if a.proc.Running() {
		if err := a.proc.Restart(); err != nil {
			writeJSON(w, map[string]any{"ok": true, "restarted": false, "restartErr": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true, "restarted": true})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "restarted": false})
}

func (a *App) handleRemoveEdge(w http.ResponseWriter, r *http.Request) {
	if err := removeEdgeHosts(); err != nil {
		writeErr(w, 500, "移除失败: "+err.Error())
		return
	}
	_ = a.store.Update(func(c *Config) {
		c.EdgeOpt = nil
	})
	a.proc.AppendLog("[cf-tunnel] 隧道边缘优选已移除")
	if a.proc.Running() {
		_ = a.proc.Restart()
	}
	writeJSON(w, map[string]any{"ok": true})
}

// handleHostsExport 生成客户端 hosts 加速行（优选 IP × 已映射域名）。
func (a *App) handleHostsExport(w http.ResponseWriter, r *http.Request) {
	count := 3
	if v := r.URL.Query().Get("count"); v != "" {
		fmt.Sscanf(v, "%d", &count)
	}
	if count < 1 {
		count = 1
	}
	if count > 10 {
		count = 10
	}
	st := a.speed.State()
	cfg := a.store.Cfg()
	ips := []string{}
	for i, res := range st.Results {
		if i >= count {
			break
		}
		ips = append(ips, res.IP)
	}
	var lines []string
	for _, m := range cfg.Mappings {
		for _, ip := range ips {
			lines = append(lines, fmt.Sprintf("%s %s", ip, m.Hostname))
		}
	}
	writeJSON(w, map[string]any{"ok": true, "lines": lines})
}
