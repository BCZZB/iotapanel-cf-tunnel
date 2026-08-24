// SPDX-License-Identifier: Apache-2.0
// 配置持久化：JSON 单文件，原子写（tmp + rename），含 API Token 故 0600。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Mapping 一条域名映射：公网 hostname → 本地 service，经隧道 ingress + DNS CNAME 双写。
type Mapping struct {
	Hostname string `json:"hostname"`           // app.example.com
	ZoneID   string `json:"zoneId"`             // hostname 所在 CF Zone
	ZoneName string `json:"zoneName,omitempty"` // 展示用
	Service  string `json:"service"`            // http://127.0.0.1:52088
	SiteID   string `json:"siteId,omitempty"`   // 联动 web-manager 站点 ID（展示用）
}

// TunnelInfo 当前管理的隧道（远程托管模式，cloudflared 用 token 运行）。
type TunnelInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"createdAt"`
}

// EdgeOpt 优选 IP 应用到隧道连接（/etc/hosts 托管块）的状态。
type EdgeOpt struct {
	IPs       []string           `json:"ips"`
	Applied   bool               `json:"applied"`
	AppliedAt time.Time          `json:"appliedAt"`
	Latency   map[string]float64 `json:"latency,omitempty"` // ip → ms（展示用）
}

// Config 全量配置。
type Config struct {
	APIToken       string      `json:"apiToken,omitempty"`
	AccountID      string      `json:"accountId,omitempty"`
	AccountName    string      `json:"accountName,omitempty"`
	Tunnel         *TunnelInfo `json:"tunnel,omitempty"`
	Mappings       []Mapping   `json:"mappings"`
	EdgeOpt        *EdgeOpt    `json:"edgeOpt,omitempty"`
	Mirror         string      `json:"mirror,omitempty"` // cloudflared 下载镜像前缀（可选）
	WMOverridePort int         `json:"wmPort,omitempty"` // web-manager 端口覆盖（0=自动发现）
}

// Store 线程安全配置仓库。
type Store struct {
	mu   sync.Mutex
	path string
	cfg  Config
}

// LoadStore 读取配置；不存在则初始化。
func LoadStore(etcDir string) (*Store, error) {
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(etcDir, "config.json")}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, &s.cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// Cfg 快照读。
func (s *Store) Cfg() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Update 读改写。
func (s *Store) Update(fn func(*Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.cfg)
	return s.persistLocked()
}

func (s *Store) persistLocked() error {
	b, err := json.MarshalIndent(&s.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
