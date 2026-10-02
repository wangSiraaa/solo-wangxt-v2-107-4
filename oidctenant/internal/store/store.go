// Package store 封装所有 PostgreSQL 访问（pgx 原生驱动）。
package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/oidctenant/internal/models"
)

var (
	// ErrNotFound 表示按主键/唯一键没有找到行。
	ErrNotFound = errors.New("store: not found")
	// ErrConsumed 表示 state 已被消费（回调重复到达）或根本不存在。
	// 对二者返回同样的错误，避免通过接口枚举有效 state。
	ErrConsumed = errors.New("store: auth request already consumed or unknown")
	// ErrConflict 表示唯一约束冲突（绑定冲突）。
	ErrConflict = errors.New("store: unique constraint violation")
	// ErrExpired 表示认证意图（或关联会话）已超过 TTL，恢复入口不能重新打开它。
	ErrExpired = errors.New("store: auth attempt expired")
	// ErrExhausted 表示认证意图的最大恢复次数已用尽。
	ErrExhausted = errors.New("store: auth attempt retries exhausted")
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// DB 暴露底层连接池（迁移/测试查询用）。
func (s *Store) DB() *pgxpool.Pool { return s.pool }

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return err
}

// ---------- tenant / provider ----------

func (s *Store) TenantBySlug(ctx context.Context, slug string) (*models.Tenant, error) {
	var t models.Tenant
	err := s.pool.QueryRow(ctx,
		`SELECT id, slug, name, created_at FROM tenants WHERE slug = $1`, slug,
	).Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

func (s *Store) TenantByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	var t models.Tenant
	err := s.pool.QueryRow(ctx,
		`SELECT id, slug, name, created_at FROM tenants WHERE id = $1`, id,
	).Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

// UpsertTenant 创建或更新租户。
func (s *Store) UpsertTenant(ctx context.Context, id uuid.UUID, slug, name string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO tenants(id, slug, name) VALUES ($1,$2,$3)
		 ON CONFLICT (id) DO UPDATE SET slug = EXCLUDED.slug, name = EXCLUDED.name`,
		id, slug, name)
	return err
}

func (s *Store) ProviderByIssuer(ctx context.Context, tenantID uuid.UUID, issuer string) (*models.Provider, error) {
	return s.provider(ctx,
		`SELECT id, tenant_id, issuer, client_id, client_secret, redirect_uris,
		        auth_time_max_age, enabled, created_at, updated_at
		 FROM identity_providers WHERE tenant_id = $1 AND issuer = $2`,
		tenantID, issuer)
}

func (s *Store) ProviderByID(ctx context.Context, tenantID, idpID uuid.UUID) (*models.Provider, error) {
	return s.provider(ctx,
		`SELECT id, tenant_id, issuer, client_id, client_secret, redirect_uris,
		        auth_time_max_age, enabled, created_at, updated_at
		 FROM identity_providers WHERE tenant_id = $1 AND id = $2`,
		tenantID, idpID)
}

func (s *Store) provider(ctx context.Context, q string, args ...any) (*models.Provider, error) {
	var p models.Provider
	err := s.pool.QueryRow(ctx, q, args...).Scan(
		&p.ID, &p.TenantID, &p.Issuer, &p.ClientID, &p.ClientSecret, &p.RedirectURIs,
		&p.AuthTimeMaxAge, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

// UpsertProvider 创建或更新租户的一个 issuer 配置。
func (s *Store) UpsertProvider(ctx context.Context, p *models.Provider) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO identity_providers
		 (id, tenant_id, issuer, client_id, client_secret, redirect_uris, auth_time_max_age, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (tenant_id, issuer) DO UPDATE SET
		   client_id = EXCLUDED.client_id,
		   client_secret = EXCLUDED.client_secret,
		   redirect_uris = EXCLUDED.redirect_uris,
		   auth_time_max_age = EXCLUDED.auth_time_max_age,
		   enabled = EXCLUDED.enabled,
		   updated_at = now()`,
		p.ID, p.TenantID, p.Issuer, p.ClientID, p.ClientSecret, p.RedirectURIs,
		p.AuthTimeMaxAge, p.Enabled)
	return err
}

// ---------- auth attempts（用户意图）与 auth requests（每次具体 OIDC 请求） ----------

// CreateAuthAttemptWithRequest 在单个事务里建立一次认证意图与其首个具体请求
// （state/nonce/PKCE）。意图与请求同时可见，任何中途失败整体回滚。
func (s *Store) CreateAuthAttemptWithRequest(ctx context.Context,
	a *models.AuthAttempt, ar *models.AuthRequest, ttl time.Duration) error {

	now := time.Now()
	a.CreatedAt = now
	a.ExpiresAt = now.Add(ttl)
	if a.Status == "" {
		a.Status = "pending"
	}
	if a.RequestSeq == 0 {
		a.RequestSeq = 1
	}
	ar.AttemptID = &a.ID
	ar.RequestSeq = a.RequestSeq
	ar.Kind = a.Kind
	ar.TenantID = a.TenantID
	ar.IDPID = a.IDPID
	ar.ReturnTo = a.ReturnTo
	ar.LinkToken = a.LinkToken
	ar.SessionID = a.SessionID

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO auth_attempts
		 (id, token, kind, tenant_id, idp_id, return_to, link_token, session_id,
		  status, request_seq, max_retries, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		a.ID, a.Token, a.Kind, a.TenantID, a.IDPID, a.ReturnTo,
		nullableStr(a.LinkToken), a.SessionID,
		a.Status, a.RequestSeq, a.MaxRetries, a.ExpiresAt); err != nil {
		return mapErr(err)
	}
	if err := insertAuthRequest(ctx, tx, ar); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func insertAuthRequest(ctx context.Context, tx pgx.Tx, ar *models.AuthRequest) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO auth_requests
		 (state, kind, tenant_id, idp_id, nonce, pkce_verifier, return_to,
		  link_token, session_id, attempt_id, request_seq)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		ar.State, ar.Kind, ar.TenantID, ar.IDPID, ar.Nonce, ar.PKCEVerifier,
		ar.ReturnTo, nullableStr(ar.LinkToken), ar.SessionID,
		ar.AttemptID, ar.RequestSeq)
	return mapErr(err)
}

// AuthAttemptByToken 按不透明恢复令牌查找认证意图。不存在即返回 ErrNotFound，
// 使调用方无法借此枚举有效令牌。
func (s *Store) AuthAttemptByToken(ctx context.Context, token string) (*models.AuthAttempt, error) {
	return s.authAttempt(ctx, `WHERE token = $1`, token)
}

func (s *Store) authAttempt(ctx context.Context, where string, args ...any) (*models.AuthAttempt, error) {
	var a models.AuthAttempt
	q := attemptSelectCols + `
	      FROM auth_attempts ` + where
	err := s.pool.QueryRow(ctx, q, args...).Scan(attemptScanArgs(&a)...)
	if err != nil {
		return nil, mapErr(err)
	}
	return &a, nil
}

// attemptColumns 是 auth_attempts 的完整读取列（SELECT 与 RETURNING 共用）。
const attemptColumns = `id, token, kind, tenant_id, idp_id, return_to, link_token, session_id,
        status, request_seq, max_retries,
        last_failure_kind, last_failure_recoverable, last_failure_at, failed_request_seq,
        created_at, expires_at, finished_at`

// attemptSelectCols / attemptScanArgs 统一 attempt 行的读取，避免多处列顺序漂移。
const attemptSelectCols = `SELECT ` + attemptColumns

func attemptScanArgs(a *models.AuthAttempt) []any {
	return []any{
		&a.ID, &a.Token, &a.Kind, &a.TenantID, &a.IDPID, &a.ReturnTo,
		&a.LinkToken, &a.SessionID, &a.Status, &a.RequestSeq, &a.MaxRetries,
		&a.LastFailureKind, &a.LastFailureRecoverable, &a.LastFailureAt, &a.FailedRequestSeq,
		&a.CreatedAt, &a.ExpiresAt, &a.FinishedAt,
	}
}

const authRequestSelect = `SELECT state, kind, tenant_id, idp_id, nonce, pkce_verifier,
	       return_to, link_token, session_id, created_at, attempt_id, request_seq
	    `

func authRequestScanArgs(ar *models.AuthRequest) []any {
	return []any{
		&ar.State, &ar.Kind, &ar.TenantID, &ar.IDPID, &ar.Nonce, &ar.PKCEVerifier,
		&ar.ReturnTo, &ar.LinkToken, &ar.SessionID, &ar.CreatedAt,
		&ar.AttemptID, &ar.RequestSeq,
	}
}

// ResumeAuthAttempt 原子地为一次“可恢复失败”的意图创建下代次具体请求。
//
// 语义保证：
//   - 只有 status=pending、未过期的意图可以恢复；过期/已完成/永久失败一律拒绝；
//   - link_b 意图额外要求关联会话仍 pending、未过期，且其 b_attempt 仍指向本意图；
//   - 已经存在未消费请求时（用户重复点击/刷新/重试）直接复用该请求，行不增加；
//   - 否则旧代次全部永久失效，request_seq+1 后插入新请求；
//   - 恢复次数超过 max_retries 时把意图置为 failed 并返回 ErrExhausted；
//   - 同一意图上的并发恢复由行级 FOR UPDATE 串行化，叠加部分唯一索引兜底。
func (s *Store) ResumeAuthAttempt(ctx context.Context, token string,
	next *models.AuthRequest) (*models.AuthAttempt, *models.AuthRequest, error) {

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var a models.AuthAttempt
	err = tx.QueryRow(ctx,
		attemptSelectCols+` FROM auth_attempts WHERE token = $1 FOR UPDATE`, token,
	).Scan(attemptScanArgs(&a)...)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}

	switch {
	case a.Status == "expired", a.ExpiresAt.Before(time.Now()):
		_, _ = tx.Exec(ctx,
			`UPDATE auth_attempts SET status='expired', finished_at=now() WHERE id=$1`, a.ID)
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrExpired
	case a.Status != "pending":
		// succeeded / failed：恢复入口不能重开。
		return nil, nil, ErrConflict
	}

	if a.LinkToken.Valid {
		// 关联场景：意图永远绑定原成员/租户/会话与未过期的关联上下文。
		var linkStatus string
		var linkExpiresAt time.Time
		var bAttemptID uuid.NullUUID
		err = tx.QueryRow(ctx,
			`SELECT status, expires_at, b_attempt_id FROM link_sessions
			 WHERE token = $1 FOR UPDATE`, a.LinkToken.String,
		).Scan(&linkStatus, &linkExpiresAt, &bAttemptID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		if err != nil {
			return nil, nil, err
		}
		if linkStatus != "pending" || linkExpiresAt.Before(time.Now()) ||
			!bAttemptID.Valid || bAttemptID.UUID != a.ID {
			// 已过期/已完成的关联不能借恢复重新打开；意图不属于该关联也拒绝。
			return nil, nil, ErrConflict
		}
	}

	// 恢复的前提：上一代次确实记录过“可恢复失败”。没有失败记录（原请求还在途、
	// 用户尚未完成与 IdP 的交互）时绝不铸造新请求，避免同一意图出现并行有效请求。
	if a.FailedRequestSeq == 0 || !a.LastFailureRecoverable ||
		!a.LastFailureAt.Valid {
		return nil, nil, ErrConflict
	}

	// 幂等：最近失败代次之后已经铸造过新代次（重复点击恢复 / 刷新 / 重试），
	// 直接复用那个仍未消费的后继请求，行不增加。
	var existing models.AuthRequest
	err = tx.QueryRow(ctx, authRequestSelect+`
	     FROM auth_requests WHERE attempt_id = $1 AND consumed_at IS NULL`, a.ID,
	).Scan(authRequestScanArgs(&existing)...)
	switch {
	case err == nil:
		// 只有当该未消费请求确实晚于最近失败代次时才算后继；否则属于异常状态。
		if existing.RequestSeq <= a.FailedRequestSeq {
			return nil, nil, ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, err
		}
		return &a, &existing, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, nil, err
	}

	// 走到这里意味着失败代次已消费失效，且尚未铸造后继——现在铸造。
	if a.RequestSeq-1 >= a.MaxRetries {
		// request_seq-1 即已经发生的尝试次数；超过允许次数则终结意图。
		if _, err := tx.Exec(ctx,
			`UPDATE auth_attempts
			 SET status='failed', finished_at=now(),
			     last_failure_kind='retry_exhausted',
			     last_failure_recoverable=false, last_failure_at=now()
			 WHERE id=$1`, a.ID); err != nil {
			return nil, nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrExhausted
	}

	newSeq := a.RequestSeq + 1
	next.AttemptID = &a.ID
	next.RequestSeq = newSeq
	next.Kind = a.Kind
	next.TenantID = a.TenantID
	next.IDPID = a.IDPID
	next.ReturnTo = a.ReturnTo
	next.LinkToken = a.LinkToken
	next.SessionID = a.SessionID
	if err := insertAuthRequest(ctx, tx, next); err != nil {
		return nil, nil, err
	}
	// request_seq 推进到新代次；失败标记保留（FailedRequestSeq 指向上一代次），
	// 因为新代次尚未消费，它不是一个“新的可恢复失败”，防止从新代次再次恢复。
	if _, err := tx.Exec(ctx,
		`UPDATE auth_attempts SET request_seq=$1 WHERE id=$2`,
		newSeq, a.ID); err != nil {
		return nil, nil, err
	}
	if a.LinkToken.Valid {
		// 关联会话的 leg B state 同步切换到新代次；旧 state 不再被接受。
		if _, err := tx.Exec(ctx,
			`UPDATE link_sessions SET b_state=$1 WHERE token=$2 AND b_attempt_id=$3`,
			next.State, a.LinkToken.String, a.ID); err != nil {
			return nil, nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	a.RequestSeq = newSeq
	return &a, next, nil
}

// RecordAuthRequestFailure 在单个事务中把刚消费的具体请求标记为失败，
// 同时把失败分类记录到意图。暂时性失败（recoverable=true）后意图仍 pending，
// 等待恢复；永久失败把意图置为 failed，任何恢复入口都不能再打开它。
func (s *Store) RecordAuthRequestFailure(ctx context.Context, attemptID uuid.UUID,
	requestSeq int, kind string, recoverable bool) (*models.AuthAttempt, error) {

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE auth_requests SET failed_at=now(), failure_kind=$1
		 WHERE attempt_id=$2 AND request_seq=$3`,
		kind, attemptID, requestSeq); err != nil {
		return nil, err
	}

	var a models.AuthAttempt
	err = tx.QueryRow(ctx,
		`UPDATE auth_attempts
		 SET last_failure_kind=$1, last_failure_recoverable=$2, last_failure_at=now(),
		     failed_request_seq=$4,
		     status = CASE WHEN $2 THEN status ELSE 'failed' END,
		     finished_at = CASE WHEN $2 THEN finished_at ELSE now() END
		 WHERE id=$3
		 RETURNING `+attemptColumns,
		kind, recoverable, attemptID, requestSeq,
	).Scan(attemptScanArgs(&a)...)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &a, nil
}

// MarkAuthAttemptSucceeded 把意图标记为完成。此后任何迟到回调（旧或新代次）都
// 只能看到已消费/不存在的 state，恢复入口也拒绝重开。
func (s *Store) MarkAuthAttemptSucceeded(ctx context.Context, attemptID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth_attempts SET status='succeeded', finished_at=now()
		 WHERE id=$1 AND status='pending'`, attemptID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// ConsumeAuthRequest 原子地取出并消费一个 state。
// 重复回调（已消费）、伪造 state，或该 state 所属意图已经终结（成功/失败/过期）
// 一律返回 ErrConsumed，避免通过接口区分“不存在”与“已终结”。
func (s *Store) ConsumeAuthRequest(ctx context.Context, state string) (*models.AuthRequest, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var ar models.AuthRequest
	err = tx.QueryRow(ctx,
		`SELECT ar.state, ar.kind, ar.tenant_id, ar.idp_id, ar.nonce, ar.pkce_verifier,
		        ar.return_to, ar.link_token, ar.session_id, ar.created_at,
		        ar.attempt_id, ar.request_seq
		 FROM auth_requests ar
		 JOIN auth_attempts aa ON aa.id = ar.attempt_id
		 WHERE ar.state = $1 AND ar.consumed_at IS NULL AND aa.status = 'pending'
		 FOR UPDATE OF ar`,
		state,
	).Scan(authRequestScanArgs(&ar)...)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConsumed
		}
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE auth_requests SET consumed_at = now() WHERE state = $1`, state); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &ar, nil
}

// DeleteExpiredAuthRequests 清理已终结/过期的具体请求与意图，防止表无限增长。
// 过期但仍 pending 的意图先显式置为 expired，确保过期状态持久化、恢复入口关闭。
func (s *Store) DeleteExpiredAuthRequests(ctx context.Context, before time.Time) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE auth_attempts SET status='expired', finished_at=now()
		 WHERE status='pending' AND expires_at < $1`, before); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM auth_requests WHERE created_at < $1`, before); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`DELETE FROM auth_attempts
		 WHERE expires_at < $1
		    OR (status <> 'pending' AND COALESCE(finished_at, created_at) < $1)`, before)
	return err
}

// ---------- 登录：按已核实身份找到或创建成员（并发安全，回调重放安全） ----------

// LoginIdentity 是回调中已通过加密校验的身份信息。
type LoginIdentity struct {
	TenantID      uuid.UUID
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
}

// LoginMemberResult 返回成员信息以及该身份是否为首次登录。
type LoginMemberResult struct {
	Member  *models.Member
	Created bool
}

// LoginOrRegisterMember 以 (tenant_id, issuer, subject) 为锚点查找/创建成员。
//
// 事务内先取事务级咨询锁，保证两个并发的首次回调不会各自插入一个成员；
// 行上的 UNIQUE(tenant_id, issuer, subject) 是第二道防线。
func (s *Store) LoginOrRegisterMember(ctx context.Context, in LoginIdentity) (*LoginMemberResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	created := false

	// pg_advisory_xact_lock 以 issuer|subject 的哈希作为 key，事务结束自动释放。
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1 || '|' || $2, 0))`,
		in.Issuer, in.Subject); err != nil {
		return nil, err
	}

	var identityID, memberID uuid.UUID
	var email string
	var emailVerified bool
	err = tx.QueryRow(ctx,
		`SELECT id, member_id, email, email_verified FROM identities
		 WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
		in.TenantID, in.Issuer, in.Subject,
	).Scan(&identityID, &memberID, &email, &emailVerified)
	switch {
	case err == nil:
		// 已有身份：刷新展示字段，复用既有成员。绝不按邮箱合并账号。
		if _, err := tx.Exec(ctx,
			`UPDATE identities SET email = $1, email_verified = $2, updated_at = now()
			 WHERE id = $3`, in.Email, in.EmailVerified, identityID); err != nil {
			return nil, err
		}
		if in.DisplayName != "" {
			_, _ = tx.Exec(ctx,
				`UPDATE members SET display_name = $1 WHERE id = $2 AND display_name = ''`,
				in.DisplayName, memberID)
		}
	case errors.Is(err, pgx.ErrNoRows):
		// 全新身份：创建成员 + 身份，二者在同一事务里。
		created = true
		memberID = uuid.New()
		if _, err := tx.Exec(ctx,
			`INSERT INTO members(id, tenant_id, display_name) VALUES ($1,$2,$3)`,
			memberID, in.TenantID, in.DisplayName); err != nil {
			return nil, mapErr(err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			uuid.New(), in.TenantID, memberID, in.Issuer, in.Subject,
			in.Email, in.EmailVerified); err != nil {
			return nil, mapErr(err)
		}
	default:
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}

	m, err := s.Member(ctx, in.TenantID, memberID)
	if err != nil {
		return nil, err
	}
	return &LoginMemberResult{Member: m, Created: created}, nil
}

func (s *Store) Member(ctx context.Context, tenantID, memberID uuid.UUID) (*models.Member, error) {
	var m models.Member
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, display_name, created_at FROM members
		 WHERE id = $1 AND tenant_id = $2`, memberID, tenantID,
	).Scan(&m.ID, &m.TenantID, &m.DisplayName, &m.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &m, nil
}

// IdentitiesOfMember 返回成员在本租户内已绑定的全部已核实身份。
func (s *Store) IdentitiesOfMember(ctx context.Context, tenantID, memberID uuid.UUID) ([]models.Identity, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, member_id, issuer, subject, email, email_verified
		 FROM identities WHERE tenant_id = $1 AND member_id = $2 ORDER BY created_at`,
		tenantID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Identity
	for rows.Next() {
		var i models.Identity
		if err := rows.Scan(&i.ID, &i.TenantID, &i.MemberID, &i.Issuer,
			&i.Subject, &i.Email, &i.EmailVerified); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// IdentityByAnchor 按业务身份锚点查找（绝不按邮箱）。
func (s *Store) IdentityByAnchor(ctx context.Context, tenantID uuid.UUID, issuer, subject string) (*models.Identity, error) {
	var i models.Identity
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, member_id, issuer, subject, email, email_verified
		 FROM identities WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
		tenantID, issuer, subject,
	).Scan(&i.ID, &i.TenantID, &i.MemberID, &i.Issuer, &i.Subject,
		&i.Email, &i.EmailVerified)
	if err != nil {
		return nil, mapErr(err)
	}
	return &i, nil
}

// ---------- sessions ----------

func (s *Store) CreateSession(ctx context.Context, tenantID, memberID uuid.UUID, tokenHash []byte, ttl time.Duration) (*models.Session, error) {
	id := uuid.New()
	now := time.Now()
	exp := now.Add(ttl)
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sessions(id, tenant_id, member_id, token_hash, created_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, tenantID, memberID, tokenHash, now, exp); err != nil {
		return nil, err
	}
	return &models.Session{ID: id, TenantID: tenantID, MemberID: memberID,
		TokenHash: tokenHash, ExpiresAt: exp}, nil
}

func (s *Store) SessionByHash(ctx context.Context, tokenHash []byte) (*models.Session, error) {
	var sess models.Session
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, member_id, token_hash, expires_at FROM sessions
		 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`,
		tokenHash,
	).Scan(&sess.ID, &sess.TenantID, &sess.MemberID, &sess.TokenHash, &sess.ExpiresAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &sess, nil
}

func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	return err
}

// ---------- link sessions ----------

// CreateLinkSessionWithAttempt 在单个事务里原子建立：关联会话、leg B 的认证意图
// （auth_attempts）与首个具体请求（auth_requests），并把 b_state / b_attempt_id
// 绑定到首代次。三者要么同时可见，要么整体回滚。
func (s *Store) CreateLinkSessionWithAttempt(ctx context.Context,
	ls *models.LinkSession, a *models.AuthAttempt, ar *models.AuthRequest, ttl time.Duration) error {

	now := time.Now()
	ls.ExpiresAt = now.Add(ttl)
	a.CreatedAt = now
	a.ExpiresAt = now.Add(ttl)
	if a.Status == "" {
		a.Status = "pending"
	}
	if a.RequestSeq == 0 {
		a.RequestSeq = 1
	}
	a.Kind = "link_b"
	a.TenantID = ls.TenantID
	a.IDPID = ls.TargetIDPID
	a.ReturnTo = "/"
	a.LinkToken = models.NullString{String: ls.Token, Valid: true}
	a.SessionID = &ls.SessionID
	ar.AttemptID = &a.ID
	ar.RequestSeq = a.RequestSeq
	ar.Kind = a.Kind
	ar.TenantID = a.TenantID
	ar.IDPID = a.IDPID
	ar.ReturnTo = a.ReturnTo
	ar.LinkToken = a.LinkToken
	ar.SessionID = a.SessionID
	ls.BState = ar.State
	ls.BAttemptID = &a.ID

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 顺序：先建 leg B 意图，再建引用它的关联会话，最后建具体请求；
	// 任一失败整体回滚。
	if _, err := tx.Exec(ctx,
		`INSERT INTO auth_attempts
		 (id, token, kind, tenant_id, idp_id, return_to, link_token, session_id,
		  status, request_seq, max_retries, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		a.ID, a.Token, a.Kind, a.TenantID, a.IDPID, a.ReturnTo,
		nullableStr(a.LinkToken), a.SessionID,
		a.Status, a.RequestSeq, a.MaxRetries, a.ExpiresAt); err != nil {
		return mapErr(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO link_sessions
		 (token, tenant_id, anchor_member_id, session_id, target_idp_id,
		  a_issuer, a_subject, a_auth_time, status, expires_at,
		  b_state, b_attempt_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11)`,
		ls.Token, ls.TenantID, ls.AnchorMemberID, ls.SessionID, ls.TargetIDPID,
		ls.AIssuer, ls.ASubject, nullableTime(ls.AAuthTime), ls.ExpiresAt,
		ls.BState, ls.BAttemptID); err != nil {
		return mapErr(err)
	}
	if err := insertAuthRequest(ctx, tx, ar); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) LinkSession(ctx context.Context, token string) (*models.LinkSession, error) {
	var ls models.LinkSession
	var aAuth, bAuth sql.NullTime
	var bAttemptID uuid.NullUUID
	err := s.pool.QueryRow(ctx,
		`SELECT token, tenant_id, anchor_member_id, session_id, target_idp_id,
		        a_issuer, a_subject, a_auth_time,
		        b_issuer, b_subject, b_email, b_auth_time, b_idp_id, b_state,
		        status, expires_at, b_attempt_id
		 FROM link_sessions WHERE token = $1`, token,
	).Scan(&ls.Token, &ls.TenantID, &ls.AnchorMemberID, &ls.SessionID,
		&ls.TargetIDPID, &ls.AIssuer, &ls.ASubject, &aAuth,
		&ls.BIssuer, &ls.BSubject, &ls.BEmail, &bAuth, &ls.BIDPID, &ls.BState,
		&ls.Status, &ls.ExpiresAt, &bAttemptID)
	if err != nil {
		return nil, mapErr(err)
	}
	ls.AAuthTime = aAuth
	ls.BAuthTime = bAuth
	if bAttemptID.Valid {
		id := bAttemptID.UUID
		ls.BAttemptID = &id
	}
	return &ls, nil
}

// AttachLinkLegB 在 leg B 回调通过校验后，原子地写入 B 的身份与本次重新认证时间。
// 只有 pending 会话、且当前 b_state 与回调 state 一致时才允许写入，重放返回 ErrConflict。
func (s *Store) AttachLinkLegB(ctx context.Context, token, state, issuer, subject, email string,
	authTime time.Time, idpID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE link_sessions
		 SET b_issuer = $1, b_subject = $2, b_email = $3, b_auth_time = $4, b_idp_id = $5,
		     b_state = ''
		 WHERE token = $6 AND status = 'pending' AND b_state = $7
		   AND b_subject = '' AND expires_at > now()`,
		issuer, subject, email, authTime, idpID, token, state)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// CompleteLink 在单个事务里完成关联，全部冲突检查与写入原子发生。
//
// 检查项：
//  1. 会话仍 pending 且未过期（token 一次性）；
//  2. A、B 两条 leg 都已完成重新认证，且认证时间都在 maxAge 之内；
//  3. A 的 (issuer,subject) 仍然锚定在发起关联的成员上；
//  4. B 不能与 A 是同一个已核实身份；
//  5. B 若已存在：必须属于同一成员（重复提交幂等成功）；属于别人则绑定冲突。
func (s *Store) CompleteLink(ctx context.Context, token string, now time.Time, maxAge time.Duration) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		tenantID, anchorMemberID, sessionID, targetIDPID uuid.UUID
		bIDPID                                           uuid.UUID
		aIssuer, aSubject, bIssuer, bSubject, bEmail     string
		status                                           string
		expiresAt                                        time.Time
		aAuth, bAuth                                     sql.NullTime
	)
	err = tx.QueryRow(ctx,
		`SELECT tenant_id, anchor_member_id, session_id, target_idp_id,
		        a_issuer, a_subject, b_issuer, b_subject, b_email, status, expires_at,
		        a_auth_time, b_auth_time, b_idp_id
		 FROM link_sessions WHERE token = $1 FOR UPDATE`, token,
	).Scan(&tenantID, &anchorMemberID, &sessionID, &targetIDPID,
		&aIssuer, &aSubject, &bIssuer, &bSubject, &bEmail, &status, &expiresAt,
		&aAuth, &bAuth, &bIDPID)
	if err != nil {
		return mapErr(err)
	}
	if status != "pending" {
		return ErrConflict
	}
	if expiresAt.Before(now) {
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrNotFound
	}
	if !aAuth.Valid || !bAuth.Valid {
		return reauthError("both identities must re-authenticate before linking")
	}
	if now.Sub(aAuth.Time) > maxAge || now.Sub(bAuth.Time) > maxAge {
		return reauthError("one or both identities did not re-authenticate recently")
	}
	if bIDPID != targetIDPID {
		return reauthError("second identity was authenticated at an unexpected provider")
	}

	var aOwner uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT member_id FROM identities
		 WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
		tenantID, aIssuer, aSubject,
	).Scan(&aOwner)
	if errors.Is(err, pgx.ErrNoRows) {
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if aOwner != anchorMemberID {
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrConflict
	}

	if aIssuer == bIssuer && aSubject == bSubject {
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrConflict
	}

	var bOwner uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT member_id FROM identities
		 WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
		tenantID, bIssuer, bSubject,
	).Scan(&bOwner)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if _, err := tx.Exec(ctx,
			`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified)
			 VALUES ($1,$2,$3,$4,$5,$6,true)`,
			uuid.New(), tenantID, anchorMemberID, bIssuer, bSubject, bEmail); err != nil {
			return mapErr(err)
		}
	case err != nil:
		return err
	case bOwner != anchorMemberID:
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrConflict
	default:
		// 已属于同一成员：幂等成功。
	}

	if _, err := tx.Exec(ctx,
		`UPDATE link_sessions SET status='completed', completed_at = now() WHERE token = $1`,
		token); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ConsumeCompletedLink 在成功回调一次性消费已完成的关联会话，随后拒绝重放。
func (s *Store) ConsumeCompletedLink(ctx context.Context, token string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE link_sessions SET status='consumed'
		 WHERE token = $1 AND status = 'completed'`, token)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// ---------- helpers ----------

func nullableStr(ns models.NullString) any {
	if !ns.Valid {
		return nil
	}
	return ns.String
}

func nullableTime(nt models.NullTime) any {
	if !nt.Valid {
		return nil
	}
	return nt.Time
}

type reauthError string

func (e reauthError) Error() string { return string(e) }

// AsReauth 判断 store 返回的错误是否为“必须重新认证”类。
func AsReauth(err error) (string, bool) {
	var r reauthError
	if errors.As(err, &r) {
		return string(r), true
	}
	return "", false
}
