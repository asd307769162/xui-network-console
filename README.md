# X-UI 网络控制台

集中查看多台 X-UI 服务器的端口、启用状态、累计流量、活跃 IP 线索和分享风险，并通过 X-UI 账号安全地切换端口状态。

## 当前能力

- 按服务器、端口、状态、IP 和归属地筛选。
- 展示端口累计流量、活跃 IP、归属地、首次/最近出现时间和风险证据。
- 通过服务端 API 读取 X-UI 入站并切换启用状态，浏览器端不接触 X-UI 密码。
- 自动关闭功能默认未启用；所有开关操作都需要人工确认。

> X-UI 原生接口不提供端口对应的来源 IP。当前页面中的 IP 风险视图是产品界面和演示数据；要获得真实 IP，需要按 `docs/REALTIME-INTEGRATION.md` 在各节点接入只读采集器。

## Docker 部署

```bash
cp .env.example .env
# 在 .env 中填写 XUI_USERNAME 和 XUI_PASSWORD
docker compose up -d --build
```

默认由 Nginx 鉴权网关监听服务器的 `8787` 端口，可通过 `http://服务器IP:8787` 访问。主程序只在 Docker 内部网络开放。部署前需在 `/opt/xui-network-console-secrets/htpasswd` 配置管理员密码哈希。

## 凭据与安全

- `.env` 已被 Git 忽略，禁止提交真实账号密码。
- X-UI 账号密码仅在服务端环境变量中保存。
- 当前节点清单位于 `lib/xui.ts`；仓库应保持私有。
- 自动封禁或自动关闭端口不应仅依据 IP 归属地，应先保留证据并人工复核。
