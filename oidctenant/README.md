# oidctenant —— 多租户 OIDC 登录与账号关联 API

无前端的后端服务，演示并落地以下安全目标：

1. **业务身份只基于已核实的提供方组合** `(tenant_id, issuer, subject)`，
   `email` 仅作展示，绝不参与账号匹配 —— 两家企业的员工邮箱相同也不会串号。
2. 完整校验 OIDC 授权码流程的**签名、受众（aud/azp）、issuer、有效期、nonce、state、PKCE**。
3. **账号关联要求两个身份各自重新认证**（OIDC `prompt=login` + `auth_time` 新鲜度窗口）。
4. **登录/关联回调重复到达不会创建多个成员**（state 一次性消费 + 咨询锁 + 唯一约束）。
5. **只允许已配置的回调地址**（精确白名单匹配）。
6. **身份令牌绝不写进日志**（只记录错误分类，不记录 code/token）。
7. **可恢复认证尝试**：提供方**暂时性**不可用时，用户意图可恢复 —— 在原意图下
   生成全新的 state/nonce/PKCE 而无需从头开始；旧请求永久失效，
   永久验证失败（签名/nonce/PKCE/受众/非法授权码）一律不可恢复。

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
| `auth_requests` | 每次具体 OIDC 请求：`state` 主键 + `nonce` + `pkce_verifier`，一次性消费（`consumed_at`），恢复后旧请求永久失效（`invalidated_at`）；归属某个 `auth_attempts` |
| `auth_attempts` | 一次用户认证**意图**（登录/关联）：状态机、尝试次数/上限、失败分类、当前有效 state、恢复能力令牌（只存 SHA-256） |
| `sessions` | 不透明会话令牌（数据库存 SHA-256 哈希） |
| `link_sessions` | 账号关联会话：A/B 两条 leg 的 issuer/subject/auth_time，一次性 token |

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
| `provider_temporarily_unavailable` | 503 | 提供方暂时性错误（网络/超时/5xx/429/发现或 JWKS 暂时不可达）；**唯一可恢复类别**，响应带恢复入口 |
| `recovery_unavailable` | 410 | 尝试已过期、重试次数耗尽或已终态；已完成流程不会因此回退 |
| `tenant_unauthorized` | 403 | 租户未启用该 issuer、provider 被禁用、跨租户使用会话 |
| `binding_conflict` | 409 | 目标身份已绑给别的成员、自关联、关联会话重放 |
| `invalid_request` | 400 | state 缺失/已用/伪造、回调地址不在白名单、参数非法 |
| `reauthentication_required` | 401 | 关联时某一身份未在 `auth_time_max_age` 窗口内重新认证 |

端点：

| 方法/路径 | 说明 |
| --- | --- |
| `GET  /healthz` | 健康检查 |
| `GET  /t/{slug}/login?issuer=...&return_to=/...` | 发起登录，302 到 IdP |
| `GET  /oauth/callback` | 登录回调（固定路径） |
| `GET|POST /oauth/recover` | 从暂时性失败恢复：GET 302 到新授权地址（浏览器）；POST 返回新 `authorization_url`（API） |
| `GET|POST /oauth/attempt` | 查询当前认证意图状态（pending/recoverable/终态），刷新/重启后决定“继续还是重来” |
| `GET  /t/{slug}/api/me` | 当前成员与其已绑定身份（需会话 Cookie `sid`） |
| `POST /t/{slug}/api/logout` | 吊销会话 |
| `POST /t/{slug}/api/links` | 发起账号关联，返回 `link_token` 与 `link_url`；body `{"issuer":"..."}` |
| `GET  /oauth/link/callback` | 关联第二身份的回调（强制重认证） |
| `GET  /t/{slug}/api/links/{token}` | 查询关联会话状态（一次性） |

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
- **可恢复认证尝试**（`auth_attempts` ↔ `auth_requests` 两层）：
  - **意图与请求分离**：一次用户意图（登录或账号关联）落一行 `auth_attempts`，
    每次对 IdP 的具体请求（state/nonce/PKCE）各落一行 `auth_requests`。
  - **只恢复暂时性错误**：令牌端点 5xx/429、网络超时/连接失败、发现文档或 JWKS
    暂时不可达才标记 `recoverable`；签名、issuer/受众、过期、**nonce**、**PKCE**、
    `invalid_grant`（旧/重放授权码）等全部终态化为 `failed_permanent`，绝不恢复。
  - **恢复即换新**：恢复在**单事务**内 `FOR UPDATE` 锁定意图，失效全部旧请求
    （`invalidated_at`），插入全新 state/nonce/PKCE 并推进 `recover_generation`；
    旧 state、旧授权码到达回调时与“未知 state”返回完全一致的 400。
  - **重复恢复幂等**：双击/刷新恢复入口或并发恢复时，事务以 `recover_generation`
    判定“后继是否已被别人创建”，已存在则复用同一后继 —— 任何时刻只有一个有效
    具体请求，16 路并发恢复也只产生一个后继（见 store 并发测试）。
  - **链接仍绑定原上下文**：链接意图的恢复必须由发起时的同一会话完成，
    并始终绑定原成员/租户/目标 IdP；`link_sessions.b_state` 与新请求原子改绑。
    关联会话一旦过期，恢复返回 410 且**不会被重新打开**。
  - **终态不可回退**：成功是条件 `UPDATE ... WHERE status='pending'`；旧/新回调
    乱序或同时到达时只有一个能越过该闸门，随后才创建成员/会话/绑定身份。
  - **持久化**：状态、`attempts/max_attempts`（`MAX_AUTH_ATTEMPTS`，默认 3）、
    失败分类、过期时间均落库；进程重启后未过期意图可凭恢复令牌继续，
    过期意图由启动清理终态化。恢复令牌只存 SHA-256，经 HttpOnly `aat` cookie
    或 API body/`Authorization: Bearer` 传递（绝不进 URL query 与日志）。
- **日志脱敏**：访问日志把 query 中的 `code/id_token/access_token/refresh_token/state/token`
  统一替换为 `[REDACTED]`；认证失败只记录分类（signature/audience/nonce/...），
  全代码路径不打印原始令牌。503 恢复入口只暴露操作信息（重试计数、入口 URL），
  不含 code/state/nonce/PKCE/token。

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

### 加密校验与可恢复尝试单元/集成测试（不需要 Keycloak）

```bash
# 纯单测：失败分类（5xx/429 可恢复；签名/nonce/PKCE/invalid_grant 永久）
go test ./internal/oidcx/...
# 纯 store 层：并发恢复唯一后继、旧请求失效、终态不回退、链接绑定与过期
go test ./internal/store/...
# 端到端（进程内模拟 IdP + 嵌入式 PostgreSQL，无需 Keycloak）：
go test ./integration/ -run 'TestRecover|TestOldStateAndCode|TestOldAndNew|TestPermanentFailures|TestOldCodeCannotPair|TestUnknownRecovery|TestIdPError' -v
```

覆盖：合法令牌基线、错误 nonce、错误受众、过期、伪造 issuer、不受信密钥签名；
以及可恢复尝试的全部验收点（临时失败后换新成功、重复恢复唯一后继、旧 state/code
被拒、永久失败不可恢复、重启后续跑、过期关联不重开、旧新回调并发不重复建成员）。

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
