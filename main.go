// SPDX-License-Identifier: Apache-2.0
// cf-tunnel：IotaPanel Cloudflare Tunnel 管理插件（纯 Go 零依赖）。
//
// 架构：单进程 ——
//  1. 管理接口：监听 $PLUGIN_BIND:$PLUGIN_PORT（默认 127.0.0.1），经面板网关 /p/cf-tunnel/ 访问
//  2. cloudflared：setsid 脱离本插件运行（插件/面板重启不中断隧道），本插件负责托管与自动拉起
//
// 低占用设计：插件本体常驻 ~8MB；cloudflared 仅在隧道启用时运行；优选 IP 测速按需执行完即释放。
// 契约（IotaPanel 插件三铁律）：监听 $PLUGIN_PORT；处理 SIGTERM 优雅退出；manifest bind 保持 127.0.0.1。
package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"
)

func main() {
	debug.SetMemoryLimit(48 << 20) // 软内存上限：空闲 ~8MB，测速峰值也受控

	port := os.Getenv("PLUGIN_PORT")
	if port == "" {
		port = "19110" // 手动运行兜底
	}
	bind := os.Getenv("PLUGIN_BIND")
	if bind == "" {
		bind = "127.0.0.1"
	}
	pluginName := os.Getenv("PLUGIN_NAME")
	if pluginName == "" {
		pluginName = "cf-tunnel"
	}
	home := os.Getenv("PANEL_HOME")
	if home == "" {
		home = filepath.Join(os.TempDir(), "cf-tunnel-dev")
	}

	app, err := NewApp(home, pluginName)
	if err != nil {
		log.Fatalf("[cf-tunnel] 初始化失败: %v", err)
	}

	admin := &http.Server{
		Addr:              bind + ":" + port,
		Handler:           app.adminMux(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		log.Printf("[cf-tunnel] 收到退出信号，优雅关闭…")
		// 注意：cloudflared 为 setsid 脱离进程，刻意不停它 —— 隧道服务不受面板/插件重启影响
		_ = admin.Close()
		time.Sleep(200 * time.Millisecond)
		log.Printf("[cf-tunnel] 已退出（cloudflared 继续运行，重启后自动认领）")
		os.Exit(0)
	}()

	go func() {
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[cf-tunnel] 管理接口启动失败: %v", err)
		}
	}()

	cfg := app.store.Cfg()
	tunnelDesc := "未配置"
	if cfg.Tunnel != nil {
		tunnelDesc = cfg.Tunnel.Name + "(" + cfg.Tunnel.ID[:8] + "…) 映射 " + strconv.Itoa(len(cfg.Mappings)) + " 条"
	}
	wmPort, wmSrc := app.wmPort()
	log.Printf("[cf-tunnel] 管理接口 %s:%s | 隧道 %s | web-manager 端口 %d(%s) | 数据目录 %s",
		bind, port, tunnelDesc, wmPort, wmSrc, app.etcDir)

	select {} // 常驻（keepalive 插件）
}
