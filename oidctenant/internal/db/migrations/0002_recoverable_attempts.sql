-- 0002_recoverable_attempts.sql
-- 可恢复认证尝试：把“一次用户意图（auth_attempts）”与
-- “每一次具体的 OIDC 请求（auth_requests 代次 request_seq）”分开记录。
--
-- 只有明确的暂时性提供方错误才允许从失败代次创建新一代 state/nonce/PKCE；
-- 旧代次行在失败时即永久失效（consumed_at + failed_at 同时置位）。

CREATE TABLE auth_attempts (
    id                       uuid PRIMARY KEY,
    -- 对外暴露的不透明恢复令牌（256 bit 熵）；主键 id 永不离开服务端。
    token                    text NOT NULL UNIQUE,
    kind                     text NOT NULL CHECK (kind IN ('login', 'link_b')),
    tenant_id                uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idp_id                   uuid NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    return_to                text NOT NULL DEFAULT '/',
    -- link_b 场景下绑定的关联会话与发起会话；登录场景为 NULL。
    link_token               text,
    session_id               uuid,
    -- pending：可能正在等待回调，也可能在等待用户点“继续”；
    -- succeeded：已完成登录/关联；failed：永久失败或重试耗尽；expired：超过意图 TTL。
    status                   text NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending', 'succeeded', 'failed', 'expired')),
    -- 当前有效请求代次（首个请求为 1，每次恢复 +1）。
    request_seq              integer NOT NULL DEFAULT 1,
    -- 允许的最大“恢复次数”（不含首次请求），在创建意图时固定。
    max_retries              integer NOT NULL DEFAULT 3,
    -- 最近一次失败的分类（仅服务端可用于判断可恢复性，错误细节永不外泄）。
    last_failure_kind        text,
    last_failure_recoverable boolean NOT NULL DEFAULT false,
    last_failure_at          timestamptz,
    -- 最近一次失败所属的具体请求代次。据此区分“后继已铸造（重复恢复幂等复用）”
    -- 与“当代次原请求仍在途、尚未失败（拒绝恢复）”。
    failed_request_seq       integer NOT NULL DEFAULT 0,
    created_at               timestamptz NOT NULL DEFAULT now(),
    -- 意图级 TTL：恢复不续期，防止一个意图被无限拉长。
    expires_at               timestamptz NOT NULL,
    finished_at              timestamptz
);
CREATE INDEX idx_authattempts_status_exp ON auth_attempts (status, expires_at);

ALTER TABLE auth_requests ADD COLUMN attempt_id uuid
    REFERENCES auth_attempts(id) ON DELETE CASCADE;
ALTER TABLE auth_requests ADD COLUMN request_seq integer NOT NULL DEFAULT 1;
ALTER TABLE auth_requests ADD COLUMN failed_at timestamptz;
ALTER TABLE auth_requests ADD COLUMN failure_kind text;
CREATE INDEX idx_authreq_attempt_seq ON auth_requests (attempt_id, request_seq);
-- 一个意图同时至多存在一个未消费请求：旧代次失效后才允许插入新代次。
CREATE UNIQUE INDEX uq_authreq_attempt_active
    ON auth_requests (attempt_id) WHERE consumed_at IS NULL;

-- 关联会话与其 leg B 认证意图绑定；恢复时在同一事务内替换 b_state。
ALTER TABLE link_sessions ADD COLUMN b_attempt_id uuid
    REFERENCES auth_attempts(id) ON DELETE CASCADE;
