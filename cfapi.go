// SPDX-License-Identifier: Apache-2.0
// Cloudflare API v4 客户端（纯标准库）：Token 校验 / Zone 列表 / 隧道 CRUD /
// 隧道 ingress 配置（远程托管）/ DNS 记录。错误统一解包 CF 的 errors[]。
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const cfAPIBase = "https://api.cloudflare.com/client/v4"

type cfClient struct {
	token string
	hc    *http.Client
}

func newCFClient(token string) *cfClient {
	return &cfClient{
		token: token,
		hc:    &http.Client{Timeout: 30 * time.Second},
	}
}

// cfError CF API 错误。
type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// do 发起请求并解包信封。result 原样返回由调用方解析。
func (c *cfClient) do(method, path string, body any) (json.RawMessage, int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, cfAPIBase+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("网络请求失败: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env cfEnvelope
	if err := json.Unmarshal(rb, &env); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, lastLines(rb, 2))
	}
	if !env.Success {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("[%d] %s", e.Code, e.Message))
		}
		if len(msgs) == 0 {
			msgs = append(msgs, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
		return nil, resp.StatusCode, fmt.Errorf("%s", strings.Join(msgs, "; "))
	}
	return env.Result, resp.StatusCode, nil
}

func lastLines(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// ---------- 类型 ----------

type cfZone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Account struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
}

type cfAccount struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfTunnelConn struct {
	ColoName           string `json:"colo_name"`
	IsPendingReconnect bool   `json:"is_pending_reconnect"`
	OriginIP           string `json:"origin_ip"`
}

type cfTunnel struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Status        string         `json:"status"`
	Token         string         `json:"token"` // 仅 create 返回
	Connections   []cfTunnelConn `json:"connections"`
	ConnsActiveAt time.Time      `json:"conns_active_at"`
	DeletedAt     *time.Time     `json:"deleted_at"`
}

type cfIngressRule struct {
	Hostname string `json:"hostname,omitempty"`
	Service  string `json:"service"`
}

type cfConfig struct {
	Ingress []cfIngressRule `json:"ingress"`
}

// ---------- API 封装 ----------

// VerifyToken 校验 Token 有效性。
// 注：Cloudflare 新版 cfat_ 前缀 token 在 /user/tokens/verify 返回 1000 Invalid，
// 改用 /zones?per_page=1 作为可用性探测（有读权限即可）。
func (c *cfClient) VerifyToken() error {
	_, _, err := c.do("GET", "/zones?per_page=1", nil)
	return err
}

// AccountsZones 一次拉全：所有 Zone + 去重后的账号列表。
func (c *cfClient) AccountsZones() ([]cfAccount, []cfZone, error) {
	var zones []cfZone
	for page := 1; page <= 3; page++ { // 最多 3 页 = 150 个 zone
		q := url.Values{}
		q.Set("per_page", "50")
		q.Set("page", fmt.Sprint(page))
		q.Set("status", "active")
		raw, _, err := c.do("GET", "/zones?"+q.Encode(), nil)
		if err != nil {
			return nil, nil, err
		}
		var pageZones []cfZone
		if err := json.Unmarshal(raw, &pageZones); err != nil {
			return nil, nil, fmt.Errorf("zone 列表解析失败: %v", err)
		}
		zones = append(zones, pageZones...)
		if len(pageZones) < 50 {
			break
		}
	}
	seen := map[string]bool{}
	var accounts []cfAccount
	for _, z := range zones {
		if !seen[z.Account.ID] {
			seen[z.Account.ID] = true
			accounts = append(accounts, cfAccount{ID: z.Account.ID, Name: z.Account.Name})
		}
	}
	if len(accounts) == 0 {
		return nil, nil, fmt.Errorf("未读到任何 Zone：请确认 Token 权限包含「Zone / Zone / Read」，且账号下有域名托管在 Cloudflare")
	}
	return accounts, zones, nil
}

// ListTunnels 列出账号下未删除的隧道。
func (c *cfClient) ListTunnels(accountID string) ([]cfTunnel, error) {
	raw, _, err := c.do("GET", "/accounts/"+accountID+"/cfd_tunnel?is_deleted=false&per_page=50", nil)
	if err != nil {
		return nil, err
	}
	var ts []cfTunnel
	if err := json.Unmarshal(raw, &ts); err != nil {
		return nil, fmt.Errorf("隧道列表解析失败: %v", err)
	}
	return ts, nil
}

// CreateTunnel 创建远程托管隧道，返回含 connector token。
func (c *cfClient) CreateTunnel(accountID, name string) (*cfTunnel, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	body := map[string]any{
		"name":          name,
		"config_src":    "cloudflare",
		"tunnel_secret": base64.StdEncoding.EncodeToString(secret),
	}
	raw, _, err := c.do("POST", "/accounts/"+accountID+"/cfd_tunnel", body)
	if err != nil {
		return nil, err
	}
	var t cfTunnel
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	if t.ID == "" || t.Token == "" {
		return nil, fmt.Errorf("创建成功但响应缺少 id/token")
	}
	return &t, nil
}

// TunnelToken 取已有隧道的 connector token（导入用）。
// 注：Cloudflare 此接口 result 为纯字符串（不是对象）。
func (c *cfClient) TunnelToken(accountID, tunnelID string) (string, error) {
	raw, _, err := c.do("GET", "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID+"/token", nil)
	if err != nil {
		return "", err
	}
	// result 可能是字符串，也可能是 {token: "..."}，两种都兼容
	var s1 string
	if err1 := json.Unmarshal(raw, &s1); err1 == nil && s1 != "" {
		return s1, nil
	}
	var r struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", err
	}
	if r.Token == "" {
		return "", fmt.Errorf("响应无 token")
	}
	return r.Token, nil
}

// GetTunnel 单查隧道（含连接状态）。
func (c *cfClient) GetTunnel(accountID, tunnelID string) (*cfTunnel, error) {
	raw, _, err := c.do("GET", "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID, nil)
	if err != nil {
		return nil, err
	}
	var t cfTunnel
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteTunnel 删除隧道（force：即使有活跃连接）。
func (c *cfClient) DeleteTunnel(accountID, tunnelID string, force bool) error {
	q := ""
	if force {
		q = "?force=true"
	}
	_, _, err := c.do("DELETE", "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID+q, nil)
	return err
}

// GetConfig 读隧道 ingress 配置。
func (c *cfClient) GetConfig(accountID, tunnelID string) (*cfConfig, error) {
	raw, _, err := c.do("GET", "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID+"/configurations", nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		Config cfConfig `json:"config"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r.Config, nil
}

// PutConfig 整体写入 ingress 配置（远程托管隧道热生效，cloudflared 无需重启）。
func (c *cfClient) PutConfig(accountID, tunnelID string, cfg *cfConfig) error {
	body := map[string]any{"config": cfg}
	_, _, err := c.do("PUT", "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID+"/configurations", body)
	return err
}

// ---------- DNS ----------

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

// dnsFind 按名字找记录（任意类型，同名冲突需先删）。
func (c *cfClient) dnsFind(zoneID, name string) ([]cfDNSRecord, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("per_page", "10")
	raw, _, err := c.do("GET", "/zones/"+zoneID+"/dns_records?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var rs []cfDNSRecord
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, err
	}
	return rs, nil
}

// UpsertTunnelCNAME 保证 hostname 指向 <tunnelID>.cfargotunnel.com（橙云代理）。
// 已存在同内容 CNAME 则幂等；其他类型同名记录先删再建。
func (c *cfClient) UpsertTunnelCNAME(zoneID, hostname, tunnelID string) error {
	target := tunnelID + ".cfargotunnel.com"
	existing, err := c.dnsFind(zoneID, hostname)
	if err != nil {
		return fmt.Errorf("查询 DNS 失败: %v", err)
	}
	for _, r := range existing {
		if r.Type == "CNAME" && r.Content == target && r.Proxied {
			return nil // 已就绪
		}
	}
	for _, r := range existing {
		if _, _, err := c.do("DELETE", "/zones/"+zoneID+"/dns_records/"+r.ID, nil); err != nil {
			return fmt.Errorf("清理旧记录 %s(%s) 失败: %v", r.Type, r.Content, err)
		}
	}
	body := map[string]any{
		"type": "CNAME", "name": hostname, "content": target,
		"proxied": true, "ttl": 1,
	}
	_, _, err = c.do("POST", "/zones/"+zoneID+"/dns_records", body)
	return err
}

// DeleteDNS 删除 hostname 的所有记录（解除映射时用）。
func (c *cfClient) DeleteDNS(zoneID, hostname string) error {
	existing, err := c.dnsFind(zoneID, hostname)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if _, _, err := c.do("DELETE", "/zones/"+zoneID+"/dns_records/"+r.ID, nil); err != nil {
			return err
		}
	}
	return nil
}
