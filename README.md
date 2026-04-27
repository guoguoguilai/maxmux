# maxmux

一个轻量级反向代理网关，让一个团队可以共用一个 **Claude Max 订阅**，通过
**虚拟 key** 给每个成员分配独立访问凭证。

本文档是项目交接说明书，面向新接手维护的同事。涵盖背景、原理、与同类项目的
对比、本地开发、发版流程、线上运维、常用操作和后续改进方向。

---

## 目录

1. [项目背景与目标](#项目背景与目标)
2. [工作原理](#工作原理)
3. [与 CLIProxyAPI 的对比分析](#与-cliproxyapi-的对比分析)
4. [项目结构](#项目结构)
5. [数据库结构](#数据库结构)
6. [本地开发](#本地开发)
7. [配置说明](#配置说明)
8. [常用运维操作](#常用运维操作)
9. [发版流程](#发版流程)
10. [线上服务器运维](#线上服务器运维)
11. [运维红线](#运维红线)
12. [后续改进方向](#后续改进方向)

---

## 项目背景与目标

Claude Max 订阅绑定单个 Anthropic 账号。官方 Claude Code CLI 通过
`claude setup-token` 拿到一个长效的 **OAuth Token**（格式
`sk-ant-oat01-...`），之后所有 API 调用都用它鉴权。

多人共用一个订阅以前的做法是把同一个 OAuth Token 配置到每个人本地——这有几个
明显缺陷：

- Token 容易泄露（被提交进 dotfiles、被日志打印、被复制粘贴）
- 没法知道谁在用、用了多少
- 没法在不影响别人的情况下停用某个人
- 多人并发使用同一个 OAuth Token 会放大触发 Anthropic 风控的风险

**maxmux** 是一个用 Go 写的轻量反向代理来解决这件事。每个成员拿到一个**虚拟
key**（比如 `sk-proxy-alice`），把 Claude Code 指向 maxmux 而不是
`api.anthropic.com`。maxmux 校验虚拟 key、从服务端 token 池里换上真实的 OAuth
Token、补上官方 CLI 应有的 headers、转发到 Anthropic，然后按虚拟 key 记录用量
做成本归属。

---

## 工作原理

### 请求流程

```
Claude Code (每个开发者)               maxmux                       api.anthropic.com
        │                                 │                                │
        │  Authorization: Bearer          │                                │
        │  sk-proxy-alice                 │                                │
        ├────────────────────────────────►│                                │
        │                                 │  ① 校验虚拟 key                │
        │                                 │  ② 检查预算 / 是否禁用         │
        │                                 │  ③ 校验 Claude Code UA         │
        │                                 │  ④ 按绑定优先级选 OAuth Token  │
        │                                 │     （跳过软禁用的）           │
        │                                 │  ⑤ 注入 oauth headers          │
        │                                 │                                │
        │                                 │  Authorization: Bearer         │
        │                                 │  sk-ant-oat01-...              │
        │                                 │  anthropic-beta: ...,oauth-... │
        │                                 │  anthropic-dangerous-...:true  │
        │                                 ├───────────────────────────────►│
        │                                 │                                │
        │                                 │◄───────────────────────────────┤
        │                                 │  ⑥ 从 SSE/JSON 解析 usage      │
        │                                 │  ⑦ 遇 429/529: 软禁用该 token  │
        │                                 │     5 分钟                     │
        │◄────────────────────────────────┤  ⑧ 持久化 usage record         │
```

### 核心概念

| 概念 | 说明 |
|------|------|
| **虚拟 key** | 开发者使用的凭证，格式 `sk-proxy-*`，存在 `virtual_keys` 表里 |
| **OAuth Token** | 真实的 Anthropic 凭证，可以配多个，由管理员在 UI 里管理 |
| **绑定 (Binding)** | 一个虚拟 key 绑定到一个或多个 OAuth Token，按优先级排序。绑定后这个虚拟 key 只会用绑定集合里的 token。**严格模式**：未绑定的 key 直接被 403 拒绝 |
| **软禁用 (Soft-disable)** | 上游返回 429/529 时，这次用的那个 token 在 5 分钟内不再被选中。下一次请求落到下一个绑定 token 上。**不跨绑定集合兜底** |
| **硬禁用 (Hard-disable)** | 管理员手动禁用 token（或虚拟 key），需要再次启用才会进入轮换 |
| **Claude Code 强制校验** | 当 `enforce_claude_code: true`（默认开启），User-Agent 不以 `claude-cli/` 开头或不包含 `claudecode` 的请求会被拒绝。挡掉 curl / 其他 SDK |

### 一些关键设计取舍

- **httputil.ReverseProxy 是单次转发的**。maxmux 没有在同一次请求里跨 token
  做"主动重试"。这让实现保持小巧，但也意味着绑定集合内的故障转移是**惰性**的：
  第一次 429 会把错误透传给客户端，**下一次**该虚拟 key 的请求才会换下一个
  绑定 token。Claude Code 客户端本身会按 `Retry-After` 自动重试，所以最终用户
  感知到的只是稍微卡了一下，不是彻底失败。
- **严格绑定模式**。没有"共享池兜底"。虚拟 key 不绑定就不能用。这样隔离的
  保证才真正有效——一个重度用户没法意外抢占别人那个 token。
- **绑定 key 不触发全局 rotate**。老的 `tokenPool.Rotate()` 在没有绑定的
  fallback 路径上还在，但严格模式下根本到不了那里。

---

## 与 CLIProxyAPI 的对比分析

[`CLIProxyAPI`](https://github.com/router-for-me/CLIProxyAPI)（在我们环境里也叫
*cliproxyapi2*）解决的是类似问题，但路线完全不同。我们在**同一台服务器上同时
运行了两个项目**，分工不同。理解差异有助于判断哪些功能值得从 CLIProxyAPI 借鉴。

| 维度 | maxmux | CLIProxyAPI |
|------|--------|-------------|
| **服务范围** | 仅 Claude | Claude、OpenAI Codex、Gemini、Qwen、Kimi、iFlow、Antigravity、Vertex、OpenAI-compat |
| **代码体量** | ~2400 行，单文件 `main.go` | ~370 个源文件 |
| **存储** | SQLite（持久化） | 仅内存（提供 export/import 做备份） |
| **成本计算** | 内置定价表，按虚拟 key 算 USD | 只记 token 数，不算钱 |
| **TLS 指纹** | 标准库 Go 默认 | uTLS 模拟 Chrome ClientHello |
| **User-Agent / Stainless 头** | 透传，仅做 UA 前缀校验 | 全套 Claude Code 设备画像伪造，按 token 缓存稳定 |
| **请求体改写** | 无——纯转发 | 重度——注入伪造的 user_id、billing header、system prompt 块、CCH 签名、tool 名重映射 |
| **请求头清洗** | 删 `Accept-Encoding`（为了解析 SSE） | 全面清洗 `X-Forwarded-*`、`Sec-Ch-Ua-*`、`X-Stainless-*`、各种网关标记 |
| **认证接入** | 本地跑 `claude setup-token`，把 token 粘贴进配置 / 管理 UI | 内置浏览器 OAuth 流程（`/auth/...`），无需手动粘贴 |
| **配额可见度** | 仅本地累加 | 一样——两边都靠解析上游响应里的 `usage` 字段；都没法拿到 Anthropic 真正的订阅配额 |
| **按用户分配** | 一等公民：`virtual_key_token_bindings` 表 + UI 编辑器 | 通过 auth metadata + access provider，更灵活但也更重 |

### 关键结论

- **maxmux 是刻意保持精简的**。一个 Go 文件、依赖极少，新人一个下午就能从头读
  完。代价是除了基本必要的之外没做反检测。
- **CLIProxyAPI 是高度复杂的**。它在 TLS、Header、Body 三个层面都主动伪装成
  官方 Claude Code 客户端。对抗检测能力强，维护面也大很多。
- **两边共用同一个根本限制**：Anthropic 没有给 OAuth Max 订阅暴露配额查询
  接口。任何"已花多少 / 还剩多少"都是基于响应体的尽力而为统计。

我们环境下的目标不是"用 maxmux 替代 CLIProxyAPI"。两者刻意分工：
- **maxmux** 负责 Claude
- **CLIProxyAPI** 负责 **GPT (OpenAI Codex)**

详见 [线上服务器运维](#线上服务器运维)。

---

## 项目结构

```
maxmux/
├── main.go             — 单文件服务（存储、KeyManager、
│                          TokenPool、proxy、admin API）
├── static/index.html   — 管理 UI（原生 JS，go:embed 嵌入）
├── Dockerfile          — 多阶段构建（golang:alpine → alpine）
├── docker-compose.yml  — 生产 compose 模板
├── release.sh          — 读 main.go 版本号的发版脚本
├── config.yaml         — 本地配置（gitignore）
├── config.yaml.example — 模板
├── keys.csv            — 批量 key seeding 模板（gitignore）
└── data/               — 开发环境的 SQLite 文件
```

---

## 数据库结构

SQLite，WAL 模式，单连接（`MaxOpenConns=1`）。所有表在启动时由
`Store.migrate()` 自动迁移。

| 表 | 用途 |
|----|------|
| `config` | 简单的 k/v 存储，目前用来兼容老的 `oauth_token` 字段迁移 |
| `virtual_keys` | 用户使用的虚拟 key。字段：`key`、`name`、`budget_limit_usd`、`daily_limit_usd`、`disabled` |
| `oauth_tokens` | 真实 Anthropic OAuth Token。字段：`id`、`token`、`name`、`disabled`、`sort_order` |
| `virtual_key_token_bindings` | 虚拟 key 与 OAuth Token 的多对多关系，带 `priority`（0 = 最高）。主键 `(virtual_key, token_id)` |
| `usage_records` | 每次上游调用一条记录：`(virtual_key, timestamp, model, input/output/cache tokens)`。`(virtual_key, timestamp)` 上有索引 |
| `sessions` | 管理员登录 session，带过期时间 |

### 级联删除

- 删除虚拟 key 会同时删它的 `usage_records` 和 `bindings`
- 删除 OAuth Token 会同时删它的 `bindings`（被绑定的虚拟 key 仍然存在，但变成
  无可用 token，严格模式下请求被拒）

### 软禁用状态（仅内存）

`TokenPool.softDisabledUntil` 是一个 `map[int]time.Time`，**不持久化**。
重启后所有软禁用计时器清空——这是合理的，因为冷却时间本来就只有 5 分钟，
Anthropic 的限流也是按时间窗口的。

---

## 本地开发

### 编译运行

```bash
# 从模板创建配置
cp config.yaml.example config.yaml
# 编辑 config.yaml——至少要设置 admin.username/password，
# 加一个 oauth token（也可以启动后从管理 UI 加）

# 开发时直接跑（不用先编译）
go run main.go -config config.yaml -data ./data/maxmux.db

# 想看更多日志加 -log-level debug
go run main.go -config config.yaml -data ./data/maxmux.db -log-level debug

# 想要二进制就编译
go build -o maxmux .
./maxmux -config config.yaml -data ./data/maxmux.db
```

### 冒烟测试

```bash
# 登录
curl -c cookies.txt -X POST http://localhost:4000/admin/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}'

# 加一个 OAuth Token
curl -b cookies.txt -X POST http://localhost:4000/admin/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"token":"sk-ant-oat01-...","name":"main"}'

# 加一个虚拟 key
curl -b cookies.txt -X POST http://localhost:4000/admin/api/keys \
  -H 'Content-Type: application/json' \
  -d '{"name":"alice","key":"sk-proxy-alice"}'

# 把虚拟 key 绑定到 token（token id 从 GET /admin/api/tokens 取）
curl -b cookies.txt -X PUT http://localhost:4000/admin/api/keys/bindings \
  -H 'Content-Type: application/json' \
  -d '{"key":"sk-proxy-alice","token_ids":[1]}'

# 使用
ANTHROPIC_BASE_URL=http://localhost:4000 \
  ANTHROPIC_AUTH_TOKEN=sk-proxy-alice \
  claude
```

### 管理 UI

打开 `http://localhost:4000/admin`，用 `config.yaml` 里的账号密码登录。UI 提供：

- 每个 key 的用量图表和成本
- 虚拟 key 增删改查、预算/日限额编辑、启用/禁用
- OAuth Token 增删改查、启用/禁用、查看每个 token 被几个 key 绑定
- Token 绑定编辑器（上下箭头调整优先级）
- 时间范围筛选、Feishu webhook 推送

---

## 配置说明

```yaml
# config.yaml
port: 4000                                   # 默认 4000
upstream: https://api.anthropic.com          # 不要改，除非测试用
oauth_token: sk-ant-oat01-LEGACY             # 可选，老的单 token 字段
oauth_tokens:                                # 推荐——多 token 列表
  - sk-ant-oat01-token-A
  - sk-ant-oat01-token-B
admin:
  username: admin
  password: CHANGE_ME                        # 必填，无默认值
virtual_keys:                                # 可选——只在第一次启动时
  - name: Alice                              #   把这些 key 写入数据库
    key:  sk-proxy-alice                     #   不会自动绑定 token
feishu_webhook: https://open.feishu.cn/...   # 可选
enforce_claude_code: true                    # 默认 true。仅在你确实想接受
                                             # curl / SDK 客户端时才设 false
```

CLI 参数：

| 参数 | 默认 | 用途 |
|------|------|------|
| `-config` | `config.yaml` | 配置文件路径 |
| `-data` | 空（内存） | SQLite 文件路径，docker 里用 `/data/maxmux.db` |
| `-log-level` | `info` | `debug`、`info`、`warn`、`error` |
| `-retention` | `30` | 用量记录保留天数，`0` = 永远保留 |

---

## 常用运维操作

下面这些是日常最高频的操作。所有操作**通过管理 UI** 完成最方便（
`http://154.29.156.229:4000/admin`），同时也给出对应的 curl 命令，方便脚本化
或紧急处理。

### 给新成员开通访问

> 场景：团队来了新人 Carol，需要给她开通 Claude Code 访问

**UI 操作**：

1. 登录管理面板
2. 在 **OAuth Tokens** 区，确保有可用的 token（如果没有，先用 `claude
   setup-token` 在线上服务器上拿一个，回到 UI 点 **+ Add Token**）
3. 在 **Virtual Keys** 区点 **+ Add Key**，输入 Name（`Carol`）和 Key
   （`sk-proxy-carol`）
4. **关键一步**：在新建的这一行的 **Bound Tokens** 列点击 `bind`，选一个
   或多个 OAuth Token 加进绑定列表，第一个是优先级最高的，**Save**
5. （可选）点 **Total Budget** / **Daily Budget** 列的 `set limit` 给她设
   预算

把 `sk-proxy-carol` 发给她，她在自己机器上：

```bash
ANTHROPIC_BASE_URL=http://154.29.156.229:4000 \
  ANTHROPIC_AUTH_TOKEN=sk-proxy-carol \
  claude
```

> ⚠️ 严格模式下**没绑定 token 的虚拟 key 直接被 403 拒绝**。新建 key 后一定
> 要立刻绑定，否则用户会看到 "this key is not bound to any OAuth token"。

**API 操作**：

```bash
# 1. 创建虚拟 key
curl -b cookies.txt -X POST http://localhost:4000/admin/api/keys \
  -H 'Content-Type: application/json' \
  -d '{"name":"Carol","key":"sk-proxy-carol"}'

# 2. 查 token id（拿到第一个 token 的 id）
curl -b cookies.txt http://localhost:4000/admin/api/tokens

# 3. 绑定（按优先级排列 token_ids 数组，0 号优先级最高）
curl -b cookies.txt -X PUT http://localhost:4000/admin/api/keys/bindings \
  -H 'Content-Type: application/json' \
  -d '{"key":"sk-proxy-carol","token_ids":[1,2]}'
```

### 给某个用户分配 / 修改绑定的 token

> 场景：Alice 现在被绑到 token A，想加上 token B 作为备用

**UI**：找到 Alice 这一行 → **Bound Tokens** 列点 `edit` → 在弹窗里
**+ Add** 把 token B 加进 chosen 列表 → 用 ↑↓ 调整顺序 → **Save**。

**API**：

```bash
curl -b cookies.txt -X PUT http://localhost:4000/admin/api/keys/bindings \
  -H 'Content-Type: application/json' \
  -d '{"key":"sk-proxy-alice","token_ids":[1,2]}'
# token_ids 是完整的新列表（PUT 是替换语义），第一个是优先级最高的
```

### 启用 / 禁用某个 OAuth Token

> 场景：发现某个 OAuth 账号被风控了，临时不要用它

**UI**：在 **OAuth Tokens** 表里找到对应行，点 **Disable**。会弹一个警告
列出有哪些虚拟 key 绑定了它——确认无误再点 OK。

**API**：

```bash
# 禁用
curl -b cookies.txt -X PUT http://localhost:4000/admin/api/tokens/disable \
  -H 'Content-Type: application/json' \
  -d '{"id":1,"disabled":true}'

# 启用
curl -b cookies.txt -X PUT http://localhost:4000/admin/api/tokens/disable \
  -H 'Content-Type: application/json' \
  -d '{"id":1,"disabled":false}'
```

> ⚠️ 如果某个虚拟 key **只**绑定了这个 token，禁用后那个用户会立刻收到 503。
> 弹窗会告诉你影响范围，禁用前最好先给受影响的 key 加个备用 token。

### 启用 / 禁用某个虚拟 key

> 场景：某个成员离职了，要回收他的访问权限

**UI**：在 **Virtual Keys** 表里找到对应行，点 **Disable**。

**API**：

```bash
curl -b cookies.txt -X PUT http://localhost:4000/admin/api/keys/disable \
  -H 'Content-Type: application/json' \
  -d '{"key":"sk-proxy-alice","disabled":true}'
```

### 设置 / 修改预算和日限额

> 场景：给 Alice 设一个每天最多花 5 美元、累计最多 100 美元的限额

**UI**：在 Alice 那一行的 **Total Budget** 或 **Daily Budget** 列点
`set limit` / `edit` → 填数字 → **Save**。`0` 表示无限制。

**API**：

```bash
curl -b cookies.txt -X PUT http://localhost:4000/admin/api/budget \
  -H 'Content-Type: application/json' \
  -d '{"key":"sk-proxy-alice","budget_limit_usd":100,"daily_limit_usd":5}'
```

> Daily 在每天 UTC 0 点重置。Budget 是累计上限。任一超额都会让请求收到 429。

### 添加一个新的 OAuth Token

> 场景：要扩充 token 池，比如多注册了一个 Anthropic Max 账号

1. 在线上服务器上（**必须是 154.29.156.229**，见运维红线）执行
   `claude setup-token`，按提示登录新账号，拿到 `sk-ant-oat01-...`
2. 管理 UI → **OAuth Tokens** → **+ Add Token** → 填一个有意义的 Name
   （比如 `Max-2`）和 token 字符串 → **Add Token**
3. 给已有的虚拟 key 把这个新 token 加进绑定列表（如果想分散流量的话）

**API**：

```bash
curl -b cookies.txt -X POST http://localhost:4000/admin/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"token":"sk-ant-oat01-NEW-TOKEN","name":"Max-2"}'
```

### 重命名虚拟 key 或 token

**UI**：点行内的 `edit` 按钮（虚拟 key 在 Name 列旁边，OAuth token 在
Name 单元格里）。

**虚拟 key 重命名 API**：

```bash
curl -b cookies.txt -X PUT http://localhost:4000/admin/api/keys/rename \
  -H 'Content-Type: application/json' \
  -d '{"key":"sk-proxy-alice","name":"Alice (PM)"}'
```

### 看用量 / 查谁在用

**UI**：主页面就是用量看板，可以按时间范围筛选、按 key 过滤，能看到每个
key 的请求数、token 数、估算成本和最近活跃时间。

**Feishu 推送**：UI 上有个 **Send to Feishu** 按钮，可以把当前用量报告
推送到飞书群。

---

## 发版流程

版本号是 `main.go` 里的 `var version = "vX.Y.Z"` 字面量。`release.sh`
读它（用 `sed`），构建带版本号 *和* `latest` 的 docker 镜像，推到 Docker
Hub 上的 `pageguo/maxmux`，最后 `git push mine master`。

### 标准发版

```bash
# 1. 改 main.go 里的版本号: var version = "v0.6.2"
# 2. 提交
git add main.go static/index.html  # 改了什么就 add 什么
git commit -m "简短描述 (vX.Y.Z)"

# 3. 打 tag
git tag v0.6.2

# 4. 发版
bash release.sh
# 推 pageguo/maxmux:v0.6.2 + :latest，然后 git push mine master
# tag 需要单独推：
git push mine v0.6.2
```

### 版本号约定

- `vX.Y.0` —— 功能新增（新管理路由、表结构变更、新配置项）
- `vX.Y.Z` (Z>0) —— 仅 bug 修复 / 小调整
- 还没到 `vX.0`；那个版本预留给虚拟 key 语义或管理 API 契约的破坏性变更

### 推送中途失败的补救

`release.sh` 顺序执行三件事：docker build、docker push、git push。如果
docker push 因为网络问题挂了，镜像已经在本地 daemon 里，重跑剩下的就行：

```bash
docker push pageguo/maxmux:vX.Y.Z
docker push pageguo/maxmux:latest
git push mine master
git push mine vX.Y.Z
```

### `release.sh` 的兼容性提示

脚本用 `sed`（不用 `grep -P`）提取版本号，保证 BSD grep（macOS 默认）和
GNU grep（Linux）都能用。如果你修改它，请保持这个兼容性。

---

## 线上服务器运维

### 服务清单

| 服务 | 服务器路径 | 用途 |
|------|------------|------|
| **maxmux** | `~/maxmux` | 团队的 Claude Code 流量 |
| **CLIProxyAPI** | `~/cliproxyapi2` | GPT (OpenAI Codex) 路由 |

服务器：**`154.29.156.229`**（CN 区域）。两个服务都用 `docker compose` 跑，
带 `restart: unless-stopped`，重启或临时崩溃后会自动恢复。

### maxmux：启动 / 重启

线上的约定是 maxmux 跑在 **`screen` session** 里——这样手动 Ctrl-C 和看日志
都方便。

`~/maxmux/cn.sh` 是一个简单的封装：

```bash
cd ~/maxmux
./cn.sh
```

脚本大致做的事是：`docker pull pageguo/maxmux:latest` → 启动 compose
stack。**注意**：因为 pull 在新容器启动**之前**，网络慢的时候这一步会让服务
中断比较久。

**推荐的发版重启流程** —— 把停服时间压到最小：

1. SSH 上去，`screen -r`（或 `screen -ls` 看 session 列表）
2. **另开一个 shell**，提前 pull 镜像（这时候老容器还在跑着）：

   ```bash
   docker pull pageguo/maxmux:latest
   ```

3. pull 完了再回到 maxmux 那个 screen
4. `Ctrl-C` 停掉前台容器
5. 按 `↑` 召回上一条命令（就是 `./cn.sh`），`Enter` 重启

这样新容器启动时镜像已经在本地缓存里了，实际中断只有几秒。

如果你不在 screen 里，全新启动：

```bash
screen -S maxmux
cd ~/maxmux
./cn.sh
# Ctrl-A d 把 session 放到后台
```

### CLIProxyAPI：启动 / 重启

```bash
cd ~/cliproxyapi2
docker compose up -d
```

已经在跑、自动重启。看日志：

```bash
docker compose logs -f
```

这个服务**只**用来路由 OpenAI Codex / GPT，**不要**把 Claude 流量走它。
两个服务的边界划清楚，升级或换其中一个不会影响另一个。

### 数据库备份

SQLite 文件在 `~/maxmux/data/`。在线热备（服务跑着的情况下）：

```bash
sqlite3 ~/maxmux/data/maxmux.db ".backup '/tmp/maxmux-$(date +%F).db'"
```

（`.backup` 用的是 SQLite 的在线备份 API，WAL 模式下安全。）

### 健康检查

```bash
curl -I http://154.29.156.229:4000/   # HEAD 应该 200
curl http://154.29.156.229:4000/admin # 管理 UI
```

---

## 运维红线

下面这些不是建议，是**底线**。违反任何一条都可能让整个共享订阅被风控盯上。

### 1. Claude 出口 IP 必须唯一

**所有 Claude 流量必须从 `154.29.156.229` 出**。具体说：

- 不要在其他服务器跑 maxmux
- 不要在别的 IP 上用同一个 Anthropic 账号登录 claude.ai 网页
- 不要在别的机器上对同一个账号再跑 `claude setup-token`
- 不要在本地直连 claude.ai / api.anthropic.com 用这个账号

Anthropic 的风控会关联**账号 + IP + 并发**。同一个账号在多个 IP 上活动是已知
最快引来审视的方式。

如果你确实需要本地拿生产的 OAuth Token 测试，请走这台服务器（比如开 SSH
隧道），**不要直连**。

### 2. 不要把 OAuth Token 带出 maxmux

OAuth Token 一旦加进 maxmux，就只允许网关使用。如果有人问"现在的 token 是
什么"，回答是"你不需要，你的虚拟 key 已经够用了"。在 maxmux 之外复用 OAuth
Token 会让成本归属和限流隔离都失效。

### 3. 保持 `enforce_claude_code: true`

关掉它就允许 curl / Python SDK / 任何脚本走网关。这正是**不应该**对着共享
订阅打的非官方客户端流量。

### 4. 服务器磁盘空间

**这台服务器目前剩余空间不多了。** 一旦磁盘满了，SQLite 写不进去——意味着
新的用量记录无法记录，最终代理本身也会因为 session / 日志写入失败而出问题。
**这是当前最紧迫的运维隐患。**

每次发版 / 重启之前，先扫一眼：

```bash
df -h ~                         # 看剩余空间
du -sh ~/maxmux/data            # SQLite + WAL 占用
docker system df                # docker 镜像 / build cache 占用
```

历史上有效的清理方法：

```bash
# 1. 清掉旧 docker 镜像（每次 pull 都会留旧版本，maxmux 和
#    CLIProxyAPI 各几次累积起来很大）。这个一般是收益最大的。
docker image prune -af

# 2. 已停止的容器、悬空 volume、闲置 network
docker container prune -f
docker volume prune -f
docker builder prune -af

# 3. journald / 系统日志（如果宿主机日志堆积了）
sudo journalctl --vacuum-size=200M

# 4. maxmux 的保留期。启动时已经按 -retention 标志清理（默认 30 天）
#    但 DB 看着大的时候值得确认下：
sqlite3 ~/maxmux/data/maxmux.db "SELECT COUNT(*) FROM usage_records;"
sqlite3 ~/maxmux/data/maxmux.db "SELECT date(timestamp), COUNT(*) FROM usage_records GROUP BY date(timestamp) ORDER BY 1 DESC LIMIT 14;"
```

如果 SQLite 文件本身很大，两个安全的手段：

1. 重启 maxmux 时用更小的 `-retention`（比如 `-retention 14`）。启动时
   会删掉超期记录。
2. 删完之后 `VACUUM` 真正缩小文件：

   ```bash
   sqlite3 ~/maxmux/data/maxmux.db "VACUUM;"
   ```

   （VACUUM 期间不要写入。先停 maxmux，运行，再启动。）

### 5. 禁用 token 之前先看依赖

UI 现在会在禁用 token 时弹警告，列出有哪些虚拟 key 绑定了它。**认真读那个
警告**。如果你禁用了 Alice 唯一绑定的 token，Alice 立刻就 503。要么先给她
加个备用 token，要么提前通知她。

---

## 后续改进方向

按"价值 / 成本"大致排序。标了 **[来自 CLIProxyAPI]** 的都是从兄弟项目可以
具体借鉴的功能。

### 待决策：发布与部署链路改造

> 这是一个**没有动手、留给下一个维护者拍板**的事情。当前发布链路是
> "Mac 上 docker buildx → push 到 `pageguo/maxmux` (Docker Hub 个人账号) →
> 服务器 docker pull"。痛点和可选方案如下，三个方案都可行，怎么选取决于
> 团队的偏好。

#### 当前痛点

1. **个人账号绑定**：镜像在 `pageguo` 个人 Docker Hub 仓库下，代码在
   `guoguoguilai` 个人 GitHub 仓库下。下一个维护者接手不顺。
2. **服务器小、网络慢**：每次发版 `docker pull` 都要等好几十秒到分钟级，
   是当前重启时服务中断的最大单一来源。
3. **buildx 跨平台编译**：在 Mac 上构建 `linux/amd64` 镜像比直接在服务器
   编译要绕一圈。

#### 候选方案

##### 方案 A：搬到 `git.agiplusone.com`，沿用 Docker

把代码和 Docker 镜像都搬到团队自托管的 `git.agiplusone.com`（推测带 Gitea
或 GitLab 风格的 Container Registry）。

```bash
# 1. 加远端
git remote add agi git@git.agiplusone.com:<group>/maxmux.git
git push agi master --tags

# 2. 改 release.sh 里的镜像名:
#    IMAGE="registry.git.agiplusone.com/<group>/maxmux"

# 3. 服务器上登录新 registry
docker login registry.git.agiplusone.com

# 4. 改 ~/maxmux/docker-compose.yml 和 ~/maxmux/cn.sh 里的镜像名
```

**优点**：完全脱离个人账号，未来可以接 CI（git.agiplusone.com 一般自带
runner）。
**缺点**：
- 第一次切换有几个细节要踩（自签证书 / `insecure-registries` 设置）
- 服务器要保管 docker login 凭证
- 没有解决"docker pull 慢"这个老问题

##### 方案 B：服务器直接 `go run` / `go build`

服务器上 git clone 源码，每次升级 `git pull` + 重启。不再走 Docker。

**关于 `go run` 是否更快的事实澄清**：`go run` 内部就是 "编译成临时二进制
→ 执行"，**编译时间和 `go build` 一样**。但它有两个隐性成本：

- **每次重启都重新编译**（即使代码没变），因为临时二进制每次都重建
- Ctrl-C 时进程树是 `go` wrapper 加子进程，杀干净有时候要 `pkill`

所以如果选这个方向，**用 `go build` 而不是 `go run`**：

```bash
# 服务器装 Go（一次性）
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version  # 确认 1.25+

# 升级流程
cd ~/maxmux
git pull
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o maxmux .
# 在 screen 里 Ctrl-C, 上一条命令 ./maxmux ... 重启
```

**优点**：
- 升级几乎瞬时——Go 的编译缓存（`~/.cache/go-build`）让代码没大变化时
  build 是秒级
- 没有 docker login / registry 凭证管理
- 调试容易，日志路径就是真实路径

**缺点**：
- 服务器小，**首次** build 会比较慢（~30-60s 编译加大量依赖）
- Linux 服务器空间紧张时，Go 的 module cache（`~/go/pkg/mod`）会占几百 MB
- 没有了 "镜像 = 不可变制品" 的保证，回滚靠 `git checkout vX.Y.Z`
  + rebuild

##### 方案 C：Mac 交叉编译 → `scp` 二进制 → 服务器直接跑（**推荐**）

服务器**完全不装 Go、不装 Docker**。所有编译在 Mac 上完成，scp 一个静态
二进制上去就行。这是最契合"服务器小、网络慢、想省麻烦"的方案。

```bash
# 在 Mac 上一键发布脚本（建议替代 release.sh）
#!/bin/bash
set -e

# 1. 交叉编译静态二进制
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -trimpath -o /tmp/maxmux-linux .

# 2. 上传到服务器
scp /tmp/maxmux-linux page@154.29.156.229:~/maxmux/maxmux.new

# 3. 服务器上原子替换（先传成 .new 再 mv，避免中途坏文件）
ssh page@154.29.156.229 "cd ~/maxmux && mv maxmux.new maxmux && chmod +x maxmux"

echo "Uploaded. SSH 进 screen, Ctrl-C, ./maxmux ... 重启"
```

**优点**：
- 升级 = scp 一个 ~15MB 文件，**几秒钟搞定**，比 docker pull 快几十倍，
  比服务器 build 也快
- 服务器小、网络慢的痛点彻底解决
- 服务器不需要装任何编译工具
- 二进制不可变，要回滚就 scp 老版本上去
- 仍然可以把代码托管在 `git.agiplusone.com`（独立的事情）

**缺点**：
- Mac 必须有源码副本（你本来就有）
- 没有 docker daemon 这层隔离——但当前 docker-compose 也没用
  cgroup limits，实质损失为零

#### 决策建议

| 优先级 | 方案 | 适用场景 |
|--------|------|----------|
| 推荐 | **C — Mac 交叉编译 + scp** | 团队规模小、服务器资源紧、希望升级时间最短 |
| 备选 | **B — 服务器 go build** | 不想在 Mac 和服务器之间传文件，希望发布全在服务器闭环 |
| 不推荐 | **A — 自托管 Docker Registry** | 除非未来要接 CI 或者有别的服务也要用同一个 registry |

**代码仓库迁移到 `git.agiplusone.com` 是独立的事情**，三个方案都可以
顺手做：

```bash
git remote add agi git@git.agiplusone.com:<group>/maxmux.git
git push agi master --tags
# 然后修改 release.sh 里的 git push 目标，或者把 mine 改成 agi
```

下一个维护者拍板后，把这一节连同 [线上服务器运维](#线上服务器运维)
一起更新。

---

### 短期

- **网页 OAuth 接入** [来自 CLIProxyAPI]。今天加 token 必须先在线上服务器
  跑 `claude setup-token`、复制结果、粘贴进 maxmux。CLIProxyAPI 在管理 UI 里
  实现了完整的 PKCE OAuth 流程，应该把这个移植过来——加新账号变成"点按钮
  → 登录 → 完成"。
- **用量看板增强** [来自 CLIProxyAPI]。CLIProxyAPI 的 TUI 通过
  `/v0/management/usage` 暴露了按 token 拆分的 RPM/TPM、模型分布、延迟
  直方图。我们后端已经有原始数据，主要是 UI/JS 投入。
- **管理页面上提示绑定语义**。一行小 banner 写明"严格模式：未绑定的 key
  无法使用"，避免新人首次升级时困惑。
- **软禁用状态持久化**到数据库——这样在 Claude 限流密集的时候重启 maxmux
  不会让一个抖动的 token 又被悄悄启用。

### 中期

- **新成员 OAuth 一站式接入**。把网页 OAuth + 自动绑定打包成一个向导：登录
  新 Anthropic 账号 → token + 虚拟 key + 绑定一次完成。
- **绑定集合内的主动重试**，不只是惰性。这就是当时刻意延期的"路径 2"重构。
  把 `httputil.ReverseProxy` 换成手写的 `http.Client` 循环，让 429 在**同一次
  请求里**跨绑定集合重试，而不是让客户端自己看到 429 再 retry。
- **TLS / 设备画像伪造** [来自 CLIProxyAPI]。目前可选——只在 Anthropic 启用
  主动指纹检测时才必要。加 uTLS + Stainless headers 大约 500 行代码，但隔离
  得很好。
- **多租户隔离**。今天管理员看到所有数据。租户范围内的管理员（比如团队
  leader）对大一些的团队会有用。

### 长期 / 锦上添花

- **配置热加载**——目前改 `config.yaml` 必须重启才生效（DB 里的状态已经可
  以热改了）。
- **Prometheus metrics 端点** —— `/metrics` 暴露按 key、按 token 的请求计数和
  延迟直方图。
- **限流事件 webhook**——Feishu 日报之外，token 被软禁用时立刻触发 webhook，
  让管理员能主动响应。
- **可选的 Postgres 替代 SQLite**——目前单写者模型对我们团队规模够用，但如果
  以后要 HA 就不行了。
- **headless 服务器用的 `maxmuxctl` CLI**——管理 API 够用但 `curl | jq` 不够
  友好。

---

## 维护者

欢迎 PR。提交非琐碎的 PR 之前，请：

1. 跑 `go build -o maxmux .`——没有 CI
2. 启动一个本地实例，把改动的代码路径跑一遍端到端（登录 → 绑定 → 使用 →
   查用量）
3. 如果改了表结构，在 `Store.migrate()` 里加对应的 `ALTER TABLE`，**同时**
   保留原有的 `CREATE TABLE`，让全新的数据库也能跑起来
4. 改 `main.go` 里的 `var version`，把发版说明写在 commit message body 里
