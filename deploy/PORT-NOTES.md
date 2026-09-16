# 端口处理备注

备注以服务器别名和入站 ID 为键，服务端保存，支持最多 2000 字。清空输入后保存即可清除内容。

VPS 使用 Wrangler 的本地 D1 存储，Compose 的 `console-data` 卷保存数据。不要执行 `docker compose down -v`，该命令会删除备注数据。备份此卷后再更新服务。

首次部署新镜像后、开放访问前初始化数据库（只执行一次）：

```sh
docker compose run --rm --no-deps xui-network-console pnpm exec wrangler d1 execute DB --local --config dist/server/wrangler.json --persist-to /app/.wrangler/state --file drizzle/0000_port_notes.sql
```

初始化后启动服务。API 由现有登录网关保护，不应将应用容器端口直接暴露到公网。已有备注数据库不要重复执行初始建表迁移。Sites 发布需要先配置 DB 并应用该迁移。
