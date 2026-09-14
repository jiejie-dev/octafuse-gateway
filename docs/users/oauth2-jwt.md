# 使用外部 OAuth2 JWT 调用 AI 模型

Proxy 可验证外部认证服务器签发的 JWT access token。登录、签发与刷新令牌由认证服务器和客户端负责；网关负责验签、关联本地用户，并执行现有额度、限流、路由和计费。原有 API Key 方式继续可用，Admin 登录方式不变。

## 1. 配置认证服务器信任关系

在 **Proxy** 配置 `JWT_AUTH_CONFIG`，值为一个 JSON 对象。未设置或为空时不启用 JWT。

```json
{
  "issuer": "https://login.example.com",
  "audience": "octafuse-gateway",
  "algorithm": "RS256",
  "jwksUrl": "https://login.example.com/.well-known/jwks.json",
  "tokenType": "at+jwt",
  "requiredScopes": ["ai:invoke"],
  "autoProvision": { "budgetMax": 10, "budgetPeriod": "monthly", "rpm": 60 }
}
```

也可以删除 `jwksUrl`，换成 PEM 格式的 **SPKI 公钥**：

```json
{
  "issuer": "https://login.example.com",
  "audience": "octafuse-gateway",
  "algorithm": "RS256",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n替换为真实公钥内容\n-----END PUBLIC KEY-----",
  "requiredScopes": ["ai:invoke"]
}
```

只需公钥，不要提供私钥。`publicKey` 与 `jwksUrl` 必须二选一；证书 `BEGIN CERTIFICATE` 和 PKCS#1 `BEGIN RSA PUBLIC KEY` 需要先转换为 SPKI 公钥。

| 字段 | 说明 |
|------|------|
| `issuer` | 必填，与 access token 的 `iss` 和用户 `external_system` 精确一致，注意尾部斜杠。一个实例配置一个签发方。 |
| `audience` | 必填，access token 的 `aud` 必须包含此值。应为网关专用 API audience。 |
| `algorithm` | 必填；支持 RS256/384/512、PS256/384/512、ES256/384。不接受 HS 系列或 `none`。 |
| `jwksUrl` | 固定的 HTTPS JWKS 地址，支持 `kid` 选择及密钥轮换。不会访问 token 中的 `jku` / `x5u`。 |
| `publicKey` | 固定 SPKI PEM 公钥，支持 JSON 换行或字面量 `\n`。更新后使用新公钥验签。 |
| `tokenType` | 默认 `at+jwt`，验证 JWT Header 的 `typ`。若服务器的 access token 使用 `JWT`，显式设置为 `JWT`，并确保专用 audience/scope 能将其与 ID token 区分。 |
| `requiredScopes` | 可选字符串数组，默认 `[]`；要求 token 的空格分隔 `scope` 字符串包含全部配置值，例如 `ai:invoke`。这是网关访问权限，不是逐模型白名单。 |
| `autoProvision` | 可选对象；设置后首次有效 JWT 请求自动创建用户和计费 Key，无需手工开通。不设置则维持预先开通模式，详情见下节。 |

必须包含 `iss`、`aud`、非空 `sub`、`exp`；验证 `exp` 及存在时的 `nbf`，允许 5 秒时钟偏差。token 最大 16 KiB。配置错误返回 503，不会绕过验证。

**Node / Docker**：在 Proxy 进程环境中设置该变量。使用项目 Node 开发命令时可在根 `.env` 写一行：

```dotenv
JWT_AUTH_CONFIG='{"issuer":"https://login.example.com","audience":"octafuse-gateway","algorithm":"RS256","jwksUrl":"https://login.example.com/.well-known/jwks.json","requiredScopes":["ai:invoke"],"autoProvision":{"budgetMax":10,"budgetPeriod":"monthly","rpm":60}}'
```

Docker Compose 需在 Proxy 服务的 `environment` 中传入 `JWT_AUTH_CONFIG: ${JWT_AUTH_CONFIG}`；仅写宿主机 `.env` 不会自动将所有变量注入容器。

**Cloudflare Workers**：在部署的 Proxy Worker 的 Variables and Secrets 中设置同名 **Secret**，值为原始 JSON（不含 shell 外层单引号）。虽然公钥不是秘密，使用 Secret 可以避免下一次部署覆盖 Dashboard 文本变量。本地 Wrangler 使用 `packages/proxy/.dev.vars` 中的同名变量。项目会生成 `wrangler.jsonc`，不要依赖直接修改生成文件保存此配置。

## 2. 自动开户或预先开通

### 自动开户（大量外部用户适用）

在 `JWT_AUTH_CONFIG` 中增加以下对象：

```json
{
  "autoProvision": {
    "budgetMax": 10,
    "budgetPeriod": "monthly",
    "rpm": 60
  }
}
```

上述配置让首次通过签名、claims 和 scope 校验的用户自动获得每月 10 个网关计费货币单位的额度，用户合计每分钟最多 60 次请求。额度以网关的计费币种为准。客户端只需携带 JWT，无需另行注册、获取或保存网关 API Key。

| 字段 | 说明 |
|------|------|
| `budgetMax` | 必填，0 到 10¹² 的金额（按网关精度保留 6 位小数）；`null` 明确表示不限额度，`0` 表示不授予付费额度。没有隐式的无限额度默认值。 |
| `budgetPeriod` | 默认 `none`（一次性额度）；也支持 `daily`、`weekly`、`monthly`，周期起点按首次开户时间及现有 UTC 重置规则计算。 |
| `rpm` | 默认 `60`，作用于用户所有 Key 的合计请求；非负整数，`null` 为不限频率，`0` 禁止需要计次的请求。 |

如果希望所有通过认证的用户都能调用，且不在网关限制额度，可以配置：

```json
{ "autoProvision": { "budgetMax": null, "rpm": 60 } }
```

网关会自动维护用于计费和日志的本地记录，按原始 `iss + sub` 唯一关联。首次开户时，用户、专用计费 Key、绑定关系、限流与两条审计记录在一个事务中提交；并发首次请求复用同一个账户，不会重复发放额度或产生多把 Key。D1、Postgres 和 MySQL 均支持，无需新增数据库迁移。

JWT 不必含 `email`。自动用户使用身份摘要生成的 `@jwt.invalid` 占位邮箱，避免用户邮箱重复或缺失影响登录。可通过后台修改显示邮箱；不会影响身份关联。`issuer` 最长 128 个字符、自动新用户的 `sub` 最长 512 个字符，与支持的数据库字段宽度一致。

默认额度和限流**只在开户时应用**。刷新 JWT 或调整 `autoProvision` 不会覆盖已存在用户的余额、限流或其他管理设置。已停用的用户、已撤销 Key、已删除的绑定关系不会自动恢复；既有手工用户仍需有效绑定。要封禁用户请停用，不要物理删除用户记录：物理删除后下一次有效 JWT 请求会被当成新用户重新开户。

### 预先开通（可选）

不设置 `autoProvision` 时，通过现有 Admin UI / Admin API 开通用户：

1. 用户 `external_system` 设置为上面的 `issuer`，`external_user_id` 设置为 JWT 的 `sub`。不按邮箱自动关联。
2. 设置用户预算或永久额度、用户限流，并保持 `status=active`。
3. 给该用户创建一把专用 API Key，例如命名为 `OAuth JWT billing`。
4. 将创建结果中的 **Key ID** 写入用户 metadata 的 `jwt_api_key_id`。该 Key 必须属于此用户并处于 `active` 状态。

以下是 Admin API 请求体示例（外部 HTTP 路径使用 `/api/admin/*`，认证使用具备相应权限的 Admin API Key）：

`POST /api/admin/users`：

```json
{
  "email": "user@example.com",
  "external_system": "https://login.example.com",
  "external_user_id": "user-123",
  "budget_max": 10,
  "budget_period": "monthly"
}
```

`POST /api/admin/users/<创建结果中的用户ID>/keys`：

```json
{ "name": "OAuth JWT billing" }
```

`PATCH /api/admin/users/<用户ID>`：

```json
{ "metadata": { "jwt_api_key_id": "替换为创建结果中的key_id" } }
```

这里填写的是 Key ID，**不是 `sk-...` 密钥明文**。该 Key 的明文仍是可用的传统凭证，请由服务端保管，无需发给用户。JWT 请求会使用此 Key 的限流和 metadata，以及用户预算、永久额度和计费倍率；日志和费用记录归属真实的 `user_id` / `api_key_id`。JWT 不会作为供应商凭证发往上游。

停用用户、撤销绑定 Key 或删除绑定后，后续 JWT 请求返回 403。用户有多把 Key 时只使用明确绑定的这一把，不会自动切换。未开通用户不会回退为匿名访问。

## 3. 客户端调用

认证服务器签发的 access token payload 示例：

```json
{
  "iss": "https://login.example.com",
  "aud": "octafuse-gateway",
  "sub": "user-123",
  "exp": 2000000000,
  "scope": "ai:invoke"
}
```

`exp` 仅为示例，实际应由认证服务器根据短期 access token 的有效期生成。

先检查用户身份和余额：

```bash
curl 'https://gateway.example.com/v1/me' \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

再使用已配置供应商和路由的模型：

```bash
curl 'https://gateway.example.com/v1/chat/completions' \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"替换为网关中的模型名称","messages":[{"role":"user","content":"你好"}]}'
```

JWT 只从 `Authorization: Bearer <token>` 接收；不要放入 URL 的 `key` 参数、`x-api-key`、`x-goog-api-key` 或 WebSocket 子协议。依赖这些位置的 SDK 仍可使用传统 API Key。浏览器原生 WebSocket 无法设置 Authorization，因此该入口不能直接使用 JWT；支持自定义握手 Header 的客户端可以使用 JWT。

## 4. 错误与轮换

- **401**：JWT 未启用，或签名、有效期、issuer/audience、token 类型等验证失败。
- **403**：scope 不足、用户未开通/停用、计费 Key 未绑定/已撤销/属于其他用户，或额度不足。
- **429**：现有 Key 或用户限流生效。
- **503**：JWT 配置不合法、公钥不可导入、JWKS 验证服务不可用，或自动开户事务失败；开户失败可重试，不会提交半成品账户。

JWKS 在每个进程/Worker isolate 中缓存至多 10 分钟；成功取回后的 30 秒内，未知 `kid` 不触发再次拉取。建议先在 JWKS 发布新公钥，再开始签发新 `kid`，并保留旧公钥直到旧 token 过期。远程请求超时为 5 秒；没有可用验证结果时拒绝访问。

这是本地 JWT 验证，不会每次请求调用 OAuth introspection。认证服务器撤销 token 不会立即同步到网关；需要即时禁止 JWT 使用时停用本地用户或撤销绑定 Key，正常过期由短期 access token 配合客户端刷新处理。

模型可见性与可调用范围沿用网关现有配置；本功能没有新增逐用户模型 ACL。Admin API 详细字段见 [Admin API 文档](../developers/api/admin.md)。
