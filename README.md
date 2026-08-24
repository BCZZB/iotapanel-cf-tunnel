# Cloudflare Tunnel 管理插件

免公网 IP / 端口的全自动内网穿透插件，为 [IotaPanel](https://github.com/plainfate/IotaPanel) 打造。
纯 Go 标准库零依赖，空闲常驻内存约 **8-12MB**，cloudflared 进程托管，掉线自动拉起。

## 功能

| 功能 | 说明 |
|---|---|
| 隧道管理 | 一键创建 / 导入 / 删除远程托管隧道（cfd_tunnel） |
| cloudflared 托管 | 自动下载二进制、启动、守护、日志查看、重启 |
| 域名映射 | 一键把域名挂到隧道：写 ingress + DNS CNAME 一步到位 |
| 联动网站管理 | 直接从 web-manager 插件读取站点列表，一键映射 |
| 优选 IP 测速 | 参考 XIU2/CloudflareSpeedTest，纯标准库实现 |
| 一键边缘加速 | 把优选 IP 写入 /etc/hosts，cloudflared 走最优边缘节点 |
| 客户端 hosts 导出 | 生成优选 IP × 映射域名的 hosts 行，本地直连加速 |

## 优选 IP 原理

1. **延迟测速**：按段容量加权随机采样 Cloudflare 官方 15 个 IPv4 段，TCP 拨测 2 次取均值，64 并发
2. **下载测速**：对延迟最优前 N 名走 `speed.cloudflare.com/__down` 直连测速，附带 PoP 机房代号
3. **双模式**：
   - 访客入口（443）：完整延迟 + 下载速度 + 机房信息，用于客户端 hosts 加速
   - 隧道边缘（7844）：仅 TCP 延迟，用于 cloudflared 边缘连接优化
4. **一键应用**：把最优 2 个 IP 写入 `/etc/hosts` 的 `region1/region2.v2.argotunnel.com`，自动备份，可一键还原

## 安全设计

- **CSRF 防护**：面板网关注入的 `X-Panel-Plugin` 标记校验 / Origin 同源校验
- **Token 安全**：API Token 加密存储在插件数据目录，仅插件进程可读
- **hosts 原子写入**：先写临时文件再 rename，绝不留半写状态
- **速率限制**：管理接口按 IP 令牌桶限流
- **审计日志**：所有操作记录到面板插件日志

## 安装

```bash
# 手动拷贝到插件目录
scp -r cf-tunnel root@server:/data/panel/plugins/
# 重启面板或在面板插件页刷新
```

安装包内含 `manifest.yaml` 与 `bin/cf-tunnel`（入口二进制），顶层目录名必须为 `cf-tunnel`。

## 使用

### 1. 配置 Cloudflare 凭证

面板侧边栏 → CF Tunnel → 设置：
- **Account ID**：Cloudflare 账号 ID（在域名概览页右侧）
- **API Token**：在 Cloudflare Dashboard → My Profile → API Tokens 创建
  - 需要权限：`Zone:DNS:Edit`、`Account:Cloudflare Tunnel:Edit`、`Zone:Read`、`Account:Read`

点「验证凭证」确认可用。

### 2. 创建隧道

- **一键创建**：点「一键完成」自动创建远程托管隧道 + 下载 cloudflared + 启动连接器
- **导入已有**：填入现有隧道 ID 和 Token 即可导入

### 3. 映射域名

隧道启动后，在「域名映射」卡片点「一键映射」，选择 web-manager 中的站点，自动：
1. 在隧道 ingress 中添加规则，转发到本地站点端口
2. 在 Cloudflare DNS 中添加 CNAME 记录指向隧道

### 4. 优选 IP

- 选择模式（访客入口 / 隧道边缘），点「开始测速」
- 测速完成后，点「🚀 一键应用到隧道连接」加速 cloudflared 边缘连接
- 或「导出客户端 hosts 加速行」把加速行写到你自己电脑的 hosts 文件

## 数据位置

```text
<PANEL_HOME>/etc/cf-tunnel/
├── config.json          # 插件配置（含加密的 API Token）
├── hosts.bak.*          # /etc/hosts 备份（首次应用前自动生成）
└── cloudflared          # 下载的 cloudflared 二进制
<PANEL_HOME>/data/cf-tunnel/
└── connector.log        # cloudflared 运行日志
```

## 开发调试（不经面板独立运行）

```bash
cd cf-tunnel
PLUGIN_PORT=19000 PANEL_HOME=/tmp/cft-dev ./bin/cf-tunnel
# 管理界面 http://127.0.0.1:19000/
```

源码构建（Go 1.21+）：

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/cf-tunnel .
```

## 注意事项

- 插件 `keepalive: true` 常驻（需要托管 cloudflared 进程）。
- 优选 IP 功能需要 root 权限写入 `/etc/hosts`（面板通常以 root 运行）。
- 首次应用边缘优选前会自动备份 hosts 文件，可随时还原。
- 测速仅按需运行，跑完即释放全部资源，无后台常驻轮询。

## License

Apache-2.0
