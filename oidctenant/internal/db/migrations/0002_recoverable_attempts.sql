-- 0002_recoverable_attempts.sql
-- 可恢复认证尝试：把“一次用户意图”（auth_attempts）与
-- “每次具体的 OIDC 请求”（auth_requests）分开记录。
--
-- 恢复规则（见 internal/store/attempts.go）：
--   * 只有明确的暂时性提供方错误（网络/5xx/429/discovery/JWKS 暂时不可达、
--     IdP 标准临时错误码）才允许从失败尝试派生新的具体请求；
--   * 每次恢复都生成全新的 state/nonce/PKCE；旧请求行永久失效
--     （invalidated_at），旧 state / 旧授权码到达回调一律按“未知或已用”拒绝；
--   * 链接场景的尝试始终绑定原成员、原会话、原租户，且关联会话未过期才可恢复。

-- 在途 auth_requests 是短命的一次性状态（现有清理按 TTL 删除），
-- 升级窗口内的行没有可归属的尝试，也不应在新代码下被接受；统一清除。
DELETE FROM auth_requests;

CREATE TABLE auth_attempts (
    id                  uuid PRIMARY KEY,
    kind                text NOT NULL CHECK (kind IN ('login', 'link_b')),
    tenant_id           uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idp_id              uuid NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    return_to           text NOT NULL DEFAULT '/',
    -- 链接场景：绑定关联会话与发起会话；普通登录为 NULL。
    link_token          text REFERENCES link_sessions(token) ON DELETE CASCADE,
    session_id          uuid,
    -- pending：尚未终态（recoverable 区分“等待 IdP 回调”与“暂时性失败待恢复”）；
    -- 其余均为终态，任何回调/恢复都不得再打开。
    status              text NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'succeeded',
                                          'failed_permanent', 'expired', 'exhausted')),
    recoverable         boolean NOT NULL DEFAULT false,
    -- attempts：已生成的具体请求数（第 1 个为初始请求）；max_attempts 为上限。
    attempts            integer NOT NULL DEFAULT 1 CHECK (attempts >= 1),
    max_attempts        integer NOT NULL CHECK (max_attempts >= 1),
    -- 当前唯一有效的具体请求 state（其余同尝试行均已消费或失效）。
    active_state        text,
    -- recover_generation：每“创建一个后继具体请求”原子加一。
    -- 恢复事务进入时先快照代数，持锁后若发现代数已被并发恢复推进，
    -- 即说明已有别的请求创建了后继 —— 本次必须复用而不是再建一个。
    recover_generation  integer NOT NULL DEFAULT 0,
    -- 只持久化失败“分类”，绝不持久化 code/token 等材料。
    last_failure_kind   text,
    -- 恢复能力令牌的 SHA-256（与 sessions.token_hash 同策略：只存哈希）。
    recovery_token_hash bytea NOT NULL UNIQUE,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    completed_at        timestamptz
);
CREATE INDEX idx_authattempts_status_exp ON auth_attempts (status, expires_at);
CREATE INDEX idx_authattempts_link ON auth_attempts (link_token);

ALTER TABLE auth_requests
    ADD COLUMN attempt_id uuid NOT NULL REFERENCES auth_attempts(id) ON DELETE CASCADE,
    ADD COLUMN invalidated_at timestamptz;
CREATE INDEX idx_authreq_attempt ON auth_requests (attempt_id);
