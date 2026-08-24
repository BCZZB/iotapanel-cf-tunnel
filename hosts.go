// SPDX-License-Identifier: Apache-2.0
// 隧道边缘优选：把测速最优 IP 写入 /etc/hosts 托管块，覆盖 cloudflared 的
// region1/region2.v2.argotunnel.com 解析（Go 解析器优先读 /etc/hosts），
// 让隧道连接走延迟更低的边缘节点。可一键移除，首次写入前自动备份。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	hostsPath     = "/etc/hosts"
	edgeBegin     = "# BEGIN cf-tunnel edge-opt (auto managed, do not edit)"
	edgeEnd       = "# END cf-tunnel edge-opt"
	edgeDomainFmt = "region%d.v2.argotunnel.com"
)

var edgeLineRe = regexp.MustCompile(`(?m)^(\d+\.\d+\.\d+\.\d+)\s+region(\d)\.v2\.argotunnel\.com`)

// hostsEdgeIPs 读当前托管块里的 IP（顺序即 region1/region2）。
func hostsEdgeIPs() []string {
	b, err := os.ReadFile(hostsPath)
	if err != nil {
		return nil
	}
	block := extractBlock(string(b))
	if block == "" {
		return nil
	}
	var ips []string
	for _, m := range edgeLineRe.FindAllStringSubmatch(block, -1) {
		if m[2] == "1" {
			ips = append(ips, m[1])
		}
	}
	return ips
}

func extractBlock(s string) string {
	i := strings.Index(s, edgeBegin)
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i:], edgeEnd)
	if j < 0 {
		return ""
	}
	return s[i : i+j+len(edgeEnd)]
}

func stripBlock(s string) string {
	i := strings.Index(s, edgeBegin)
	if i < 0 {
		return s
	}
	j := strings.Index(s[i:], edgeEnd)
	if j < 0 {
		return s[:i]
	}
	return s[:i] + s[i+j+len(edgeEnd):]
}

// applyEdgeHosts 写入托管块（ip1→region1，ip2→region2；不足则重复用最优的）。
func applyEdgeHosts(ips []string, backupDir string) error {
	if len(ips) == 0 {
		return fmt.Errorf("没有可用的优选 IP")
	}
	if len(ips) < 2 {
		ips = []string{ips[0], ips[0]}
	}
	b, err := os.ReadFile(hostsPath)
	if err != nil {
		return err
	}
	cur := string(b)
	// 首次写入前备份
	if !strings.Contains(cur, edgeBegin) {
		_ = os.MkdirAll(backupDir, 0o755)
		bak := filepath.Join(backupDir, fmt.Sprintf("hosts.bak.%d", time.Now().Unix()))
		_ = os.WriteFile(bak, b, 0o644)
	}
	ns := strings.TrimRight(stripBlock(cur), "\n") + "\n\n" + edgeBegin + "\n" +
		fmt.Sprintf("%s "+edgeDomainFmt+"\n", ips[0], 1) +
		fmt.Sprintf("%s "+edgeDomainFmt+"\n", ips[1], 2) +
		edgeEnd + "\n"
	tmp := "/etc/hosts.cf-tunnel.tmp"
	if err := os.WriteFile(tmp, []byte(ns), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, hostsPath)
}

// removeEdgeHosts 移除托管块。
func removeEdgeHosts() error {
	b, err := os.ReadFile(hostsPath)
	if err != nil {
		return err
	}
	ns := strings.TrimRight(stripBlock(string(b)), "\n") + "\n"
	if ns == string(b) {
		return nil
	}
	tmp := "/etc/hosts.cf-tunnel.tmp"
	if err := os.WriteFile(tmp, []byte(ns), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, hostsPath)
}
