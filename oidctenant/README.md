# oidctenant —— 多租户 OIDC 登录与账号关联 API

无前端的后端服务，演示并落地以下安全目标：

1. **业务身份只基于已核实的提供方组合** `(tenant_id, issuer, subject)`，
   `email` 仅作展示，绝不参与账号匹配 —— 两家企业的员工邮箱相同也不会串号。
2. 完整校验 OIDC 授权码流程的**签名、受众（aud/azp）、issuer、有效期、nonce、state、PKCE**。
3. **账号关联要求两个身份各自重新认证**（OIDC `prompt=login` + `auth_time` 新鲜度窗口）。
4. **登录/关联回调重复到达不会创建多个成员**（state 一次性消费 + 咨询锁 + 唯一约束）。
5. **只允许已配置的回调地址**（精确白名单匹配）。
6. **身份令牌绝不写进日志**（只记录错误分类，不记录 code/token）。

## 目录结构

```
cmd/server/             HTTP 服务入口（含过期 state 定时清理）
cmd/seed/               幂等写入租户与 IdP 配置
internal/config/        环境配置
internal/db/            pgx 连接池 + 嵌入式 SQL 迁移
internal/models/        持久化数据结构
internal/store/         所有 PostgreSQL 访问（事务、咨询锁、原子关联）
internal/oidcx/         go-oidc + oauth2 封装（发现/校验/交换/PKCE/nonce）
internal/auth/          state/nonce/PKCE/会话令牌随机值与哈希、回调白名单
internal/api/           HTTP handler：登录、回调、me、登出、账号关联
deploy/keycloak/import  acme / globex 两个测试 realm（含同邮箱用户）
deploy/seed.json        租户/IdP 的 seed 规格
integration/            针对真实 Keycloak + 真实 PostgreSQL 的端到端集成测试
```

## 数据模型要点

| 表 | 关键约束 / 含义 |
| --- | --- |
| `tenants` | 租户 |
| `identity_providers` | 租户**授权**的 `(issuer, client_id, secret, redirect_uris[])`，按 `(tenant_id, issuer)` 唯一 |
| `members` | 租户内的成员（业务账号） |
| `identities` | 已核实身份；**`UNIQUE(tenant_id, issuer, subject)` 是身份锚点**；`email` 无唯一约束 |
| `auth_requests` | 进行中的授权请求：`state` 主键 + `nonce` + `pkce_verifier`，一次性消费（`consumed_at`）；属于某个 `auth_attempts` 代次（`attempt_id`,`request_seq`），失败时置 `failed_at` |
| `auth_attempts` | **一次用户认证意图**（登录/关联），跨多次具体 OIDC 请求存活：持久化 `status`、当前 `request_seq`、`max_retries`、最近失败分类与可恢复性、意图级 `expires_at` |
| `sessions` | 不透明会话令牌（数据库存 SHA-256 哈希） |
| `link_sessions` | 账号关联会话：A/B 两条 leg 的 issuer/subject/auth_time，一次性 token；leg B 经 `b_attempt_id`/`b_state` 绑定当前有效代次 |

> 关联外部身份时，身份行的 `tenant_id` 是**发起关联的租户**。
> 因此 A 公司成员关联 B 公司 IdP 的身份，锚点是 `(A租户, B的issuer, subject)`，
> 与 B 公司自己的同名身份互不影响。

## API

所有业务错误返回稳定的 JSON：

```json
{ "error": "<error_type>", "message": "<human readable>" }
```

| error_type | HTTP | 触发场景 |
| --- | --- | --- |
| `authentication_failed` | 401 | 签名/受众/issuer/过期/nonce/PKCE/授权码交换失败、会话无效 |
| `tenant_unauthorized` | 403 | 租户未启用该 issuer、provider 被禁用、跨租户使用会话 |
| `binding_conflict` | 409 | 目标身份已绑给别的成员、自关联、关联会话重放 |
| `invalid_request` | 400 | state 缺失/已用/伪造、回调地址不在白名单、参数非法 |
| `reauthentication_required` | 401 | 关联时某一身份未在 `auth_time_max_age` 窗口内重新认证 |
| `provider_temporarily_unavailable` | 503 | **暂时性**提供方错误（网络不可达/5xx/429/`temporarily_unavailable`），响应带安全的 `resume_url` |
| `attempt_unavailable` | 410/409 | 恢复入口不可用：意图不存在/过期/已终结/不属于当前会话（410），或重试次数耗尽（409） |

端点：

| 方法/路径 | 说明 |
| --- | --- |
| `GET  /healthz` | 健康检查 |
| `GET  /t/{slug}/login?issuer=...&return_to=/...` | 发起登录，302 到 IdP（同时创建意图与首代次请求，并下发 HttpOnly 的 `aat` 意图 Cookie） |
| `GET  /oauth/callback` | 登录回调（固定路径） |
| `GET  /oauth/resume?attempt=...` | **安全重试**：仅当上代次是明确暂时故障时，作废旧请求并铸造全新 state/nonce/PKCE，302 到 IdP；重复调用在新代次未消费时幂等复用同一后继 |
| `GET  /oauth/attempt?attempt=...`（或 `aat` Cookie） | 查询登录意图粗粒度状态：`active`/`recoverable`/`succeeded`/`failed`/`expired`（不含失败细节） |
| `GET  /t/{slug}/api/me` | 当前成员与其已绑定身份（需会话 Cookie `sid`） |
| `POST /t/{slug}/api/logout` | 吊销会话 |
| `POST /t/{slug}/api/links` | 发起账号关联，返回 `link_token`、`attempt_token` 与 `link_url`；body `{"issuer":"..."}` |
| `GET  /oauth/link/callback` | 关联第二身份的回调（强制重认证） |
| `GET  /oauth/link/resume?attempt=...` | 关联场景的安全重试（需发起它的同一会话 Cookie，仍强制 `prompt=login`） |
| `GET  /oauth/link/attempt?attempt=...` | 查询关联意图状态（需同一会话） |
| `GET  /t/{slug}/api/links/{token}` | 查询关联会话状态（一次性） |

可恢复失败的 503 响应形如（不回显 state/nonce/PKCE/code/令牌，也不回显提供方细节）：

```json
{
  "error": "provider_temporarily_unavailable",
  "message": "the identity provider is temporarily unavailable; you can safely retry",
  "recoverable": true,
  "resume_url": "http://app/oauth/resume?attempt=<opaque>",
  "attempt_token": "<opaque>",
  "attempts_used": 1,
  "attempts_allowed": 4
}
```

## 安全实现细节

- **state / nonce / PKCE**：均为 ≥256/128-bit 加密随机值，服务端持久化；
  PKCE 使用 S256；回调时 state 行被 `SELECT ... FOR UPDATE` 原子取出并标记消费，
  未知 state 与已消费 state 返回完全一致的错误（不泄露有效性）。
- **ID token 校验**（`internal/oidcx`，基于 coreos/go-oidc v3）：
  - 签名经 IdP JWKS 验证；go-oidc 的远程 KeySet 在遇到未知 `kid` 时自动重取 JWKS，
    **密钥轮换对应用透明**；
  - `iss` 必须等于发现文档 issuer；`aud` 必须包含本 client_id；`azp`（若有）必须等于本 client；
  - 过期/nbf/iat 由 go-oidc 校验；`nonce` 与 state 行中的值逐字节比较。
- **重复回调不重复建成员**：`LoginOrRegisterMember` 在事务内先取
  `pg_advisory_xact_lock(hashtextextended(issuer|subject))`，再查/插成员与身份；
  叠加 `UNIQUE(tenant_id, issuer, subject)`，并发首次登录也只产生一个成员。
- **账号关联双重认证**：发起记录 A 的认证时刻；对 B 的授权请求强制
  `prompt=login&max_age=0`，回调核对 IdP 的 `auth_time`；
  `CompleteLink` 在单事务里复核两条 leg 的新鲜度、A 锚点未被改动、B 非自身、
  B 是否已属于他人（冲突则整体回滚，不写入）。
- **回调白名单**：`redirect_uri` 与 `identity_providers.redirect_uris` 做**精确**匹配，
  不做前缀/通配，杜绝 open redirect。
- **可恢复认证尝试（意图 vs. 具体请求）**：
  - `auth_attempts` 记录一次用户意图（状态/最大重试/失败分类/到期），`auth_requests`
    记录每次具体 OIDC 请求（代次 `request_seq` + 独立的 state/nonce/PKCE）。
  - 恢复在单事务（意图行 `FOR UPDATE`）内完成：**只有上一代次记录了明确的暂时性
    提供方故障**（网络不可达、HTTP 5xx/429、`temporarily_unavailable`）才铸造新一代；
    签名、issuer、audience、过期、nonce、PKCE/`invalid_grant`、claims 等**永久失败
    一律不可恢复**，意图直接终结。
  - 旧代次在失败时即永久失效；部分唯一索引
    `auth_requests(attempt_id) WHERE consumed_at IS NULL` 保证一个意图同时只有一个
    未消费请求，重复/并发恢复只复用同一后继。
  - 回调消费要求意图仍 `pending`：已成功/失败/过期的意图、旧 state、旧授权码到达
    全部被拒；意图成功状态的抢占（登录）与一次性 state + `AttachLinkLegB` 守卫
    （关联）保证刷新、重启、回调乱序、新旧回调同时到达都不会重复建成员/重复绑身份
    或使已完成流程回退。
  - 关联恢复仍绑定原成员、原租户、原发起会话与**未过期**的 `link_sessions`；
    过期关联在恢复与回调两处都不能被重新打开。意图 TTL 独立持久化、恢复不续期，
    因此重启后未过期尝试可继续、已过期尝试不会复活。
- **日志脱敏**：访问日志把 query 中的 `code/id_token/access_token/refresh_token/state/token`
  统一替换为 `[REDACTED]`；认证失败只记录分类（signature/audience/nonce/...），
  全代码路径不打印原始令牌。

## 本地运行

需要 Go 1.23+、Docker（用于 Postgres 与 Keycloak）。

```bash
# 1) 起 Postgres + Keycloak（自动导入两个 realm）
docker compose -f deploy/docker-compose.yml up -d

# 2) 等 Keycloak 就绪后，写入租户/IdP 配置
export DATABASE_URL=postgres://oidc:oidc@localhost:5432/oidctenant?sslmode=disable
go run ./cmd/seed -file deploy/seed.json

# 3) 启动应用（回调固定为 BASE_URL + /oauth/callback）
BASE_URL=http://localhost:8080 ADDR=:8080 \
DATABASE_URL=postgres://oidc:oidc@localhost:5432/oidctenant?sslmode=disable \
  go run ./cmd/server
```

测试账号（两个 realm 各有一个 `alice@example.com`，刻意同邮箱）：

| realm | 用户名 | 密码 | 邮箱 |
| --- | --- | --- | --- |
| acme | `alice` | `alice-pass` | alice@example.com |
| acme | `carol` | `carol-pass` | carol@example.com |
| globex | `alice.globex` | `aliceg-pass` | alice@example.com |
| globex | `bob` | `bobg-pass` | bob@example.com |

浏览器手动走一遍（无前端，直接访问启动 URL）：

```
http://localhost:8080/t/acme/login?issuer=http://localhost:8180/realms/acme
```

## 测试

### 加密校验单元测试（不需要外部依赖）

```bash
go test ./internal/oidcx/...
```

覆盖：合法令牌基线、错误 nonce、错误受众、过期、伪造 issuer、不受信密钥签名。

### 端到端集成测试（真实 Keycloak + 真实 PostgreSQL）

测试用 `fergusstrange/embedded-postgres` 在进程内拉起真实 PostgreSQL，
但需要一个已导入 realm 的本地 Keycloak（见上）。可用 `KC_BASE_URL` 覆盖地址。

```bash
# Keycloak 已运行且导入了 acme/globex realm（并为测试端口注册回调）后：
KC_BASE_URL=http://localhost:8180 go test ./integration/... -v
```

> 集成测试默认把应用起在 **18080** 端口，因此需要在两个 realm 的 `*-rp` 客户端
> 额外注册 `http://localhost:18080/oauth/callback` 与
> `http://localhost:18080/oauth/link/callback`（生产部署只注册真实端口即可）。

集成用例与题目要求一一对应：

| 用例 | 验证内容 |
| --- | --- |
| `TestCrossTenantSameEmailIsolation` | **跨租户同邮箱**：两个 alice@example.com 落到不同 member；跨租户会话 403 |
| `TestLoginCallbackReplayDoesNotDuplicateMember` | 登录回调重放：第二次 400，成员/身份仍各 1 条 |
| `TestConcurrentFirstLoginsDoNotDuplicateMember` | 并发首次登录（咨询锁+唯一约束）只建一个成员 |
| `TestAuthorizationCodeReplay` | **授权码重复使用**：state 已消费即拒绝 |
| `TestStaleCodeWithFreshStateIsAuthnFailure` | 新 state + 旧 code：Keycloak invalid_grant → 401 `authentication_failed` |
| `TestUnknownAndReplayedState` | 伪造/已用 state 行为一致 |
| `TestSigningKeyRotation` | **密钥轮换**：新增更高优先级 RSA key 后不重启应用即可验证新 kid，旧 kid 仍在 JWKS |
| `TestAccountLinkingHappyPath` | 两个身份各自重认证后关联，一个成员持有两条已核实身份 |
| `TestLinkConflictWhenTargetAlreadyBound` | **绑定冲突**：目标身份已属他人 → 409 `binding_conflict`，不被抢占 |
| `TestLinkSameEmailAcrossTenants` | 跨租户**同邮箱**两身份也能正确关联（按 issuer+subject 而非邮箱） |
| `TestLinkRequiresReauthentication` | 认证超过新鲜度窗口 → 401 `reauthentication_required` |
| `TestLinkCannotBeReplayed` | 关联 state/token 一次性，重放 400，不产生第三条身份 |
| `TestUnauthorizedIssuerForTenant` | 未授权 issuer → 403 `tenant_unauthorized` |
| `TestRedirectURIMustBeWhitelisted` | 未登记回调地址 → 400 `invalid_request` |
| `TestLinkRejectsDisabledProvider` | 关联前禁用 provider 授权 → 403 `tenant_unauthorized` |
| `TestWrongPasswordIsAuthnFailure` | IdP 凭证错误不产生会话/成员 |

## 生产化前还应补充（本项目刻意省略）

- provider `client_secret` / 会话存储的 KMS 加密与静态加密；
- CSRF 防护（state 已绑定浏览器会话，仍建议对发起端点加 CSRF token）；
- refresh token 轮转、会话固定防护、`sid`/`jti` 反向注销（back-channel logout）；
- issuer 级别允许的签名算法/时钟偏移（leeway）做成可配置；
- 审计日志（记录谁在何时把哪个 `(issuer,subject)` 关联给了哪个 member）。
