package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/example/oidctenant/internal/models"
)

// 本文件实现“可恢复认证尝试”的全部持久化原语。
//
// 两层模型：
//   - auth_attempts：一次用户意图（登录 / 关联），记录状态、重试计数、
//     失败分类与恢复能力令牌（只存哈希）；
//   - auth_requests：该意图下每一次具体的 OIDC 请求（state/nonce/PKCE）。
//
// 不变量：
//  1. 一个 pending 尝试至多有一个“有效”具体请求（active_state 指向它，
//     其余行 consumed_at / invalidated_at 非空）；
//  2. 从暂时性失败恢复时，旧请求行在同一事务内永久失效并写入全新行；
//  3. 终态（succeeded / failed_permanent / expired / exhausted）只能由
//     条件 UPDATE 进入，任何迟到回调或恢复都不能把终态回退；
//  4. 链接尝试始终绑定原 link_token / session_id / tenant_id / idp_id，
//     且关联会话仍 pending、未过期才允许恢复。

// CreateAttemptInput 是一次新认证意图的入参（含首个具体请求的随机值）。
type CreateAttemptInput struct {
	ID                uuid.UUID
	Kind              string
	TenantID          uuid.UUID
	IDPID             uuid.UUID
	ReturnTo          string
	LinkToken         string // 普通登录为空
	SessionID         *uuid.UUID
	RecoveryTokenHash []byte
	State             string
	Nonce             string
	PKCEVerifier      string
}

// CreateLoginAttempt 在单事务内创建登录意图与其首个具体请求。
func (s *Store) CreateLoginAttempt(ctx context.Context, in *CreateAttemptInput,
	ttl time.Duration, maxAttempts int) (*models.AuthAttempt, error) {

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now()
	if err := insertAttempt(tx, ctx, in, now, now.Add(ttl), maxAttempts); err != nil {
		return nil, err
	}
	if err := insertAuthRequest(tx, ctx, in); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return s.AttemptByID(ctx, in.ID)
}

// LinkAttemptInput 是链接意图的入参：意图 + 关联会话（leg A 的锚点）。
type LinkAttemptInput struct {
	Attempt        CreateAttemptInput
	AnchorMemberID uuid.UUID
	TargetIDPID    uuid.UUID
	AIssuer        string
	ASubject       string
	AAuthTime      time.Time
	LinkTTL        time.Duration
}

// CreateLinkAttempt 在单事务内创建：关联会话（leg A 锚点）+ 链接意图 +
// leg B 的首个具体请求，并把 b_state 绑定到该请求。
func (s *Store) CreateLinkAttempt(ctx context.Context, in *LinkAttemptInput,
	attemptTTL time.Duration, maxAttempts int) (*models.AuthAttempt, error) {

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	a := &in.Attempt
	now := time.Now()
	linkExpires := now.Add(in.LinkTTL)
	if _, err := tx.Exec(ctx,
		`INSERT INTO link_sessions
		 (token, tenant_id, anchor_member_id, session_id, target_idp_id,
		  a_issuer, a_subject, a_auth_time, b_state, status, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10)`,
		a.LinkToken, a.TenantID, in.AnchorMemberID, a.SessionID, in.TargetIDPID,
		in.AIssuer, in.ASubject, in.AAuthTime, a.State, linkExpires); err != nil {
		return nil, mapErr(err)
	}

	attemptExpires := now.Add(attemptTTL)
	if err := insertAttempt(tx, ctx, a, now, attemptExpires, maxAttempts); err != nil {
		return nil, err
	}
	if err := insertAuthRequest(tx, ctx, a); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return s.AttemptByID(ctx, a.ID)
}

func insertAttempt(tx pgx.Tx, ctx context.Context, in *CreateAttemptInput,
	now, expiresAt time.Time, maxAttempts int) error {

	var linkToken any
	if in.LinkToken != "" {
		linkToken = in.LinkToken
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO auth_attempts
		 (id, kind, tenant_id, idp_id, return_to, link_token, session_id,
		  status, attempts, max_attempts, active_state, recovery_token_hash,
		  created_at, updated_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',1,$8,$9,$10,$11,$11,$12)`,
		in.ID, in.Kind, in.TenantID, in.IDPID, in.ReturnTo, linkToken, in.SessionID,
		maxAttempts, in.State, in.RecoveryTokenHash, now, expiresAt)
	return mapErr(err)
}

func insertAuthRequest(tx pgx.Tx, ctx context.Context, in *CreateAttemptInput) error {
	var linkToken, sessionID any
	if in.LinkToken != "" {
		linkToken = in.LinkToken
	}
	if in.SessionID != nil {
		sessionID = *in.SessionID
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO auth_requests
		 (state, kind, tenant_id, idp_id, attempt_id, nonce, pkce_verifier,
		  return_to, link_token, session_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		in.State, in.Kind, in.TenantID, in.IDPID, in.ID, in.Nonce,
		in.PKCEVerifier, in.ReturnTo, linkToken, sessionID)
	return mapErr(err)
}

// attemptColumns 是 auth_attempts 的规范列集合（与 scanAttempt 配对）。
const attemptColumns = `id, kind, tenant_id, idp_id, return_to, link_token, session_id,
	status, recoverable, attempts, max_attempts, recover_generation, active_state,
	last_failure_kind, recovery_token_hash, created_at, updated_at, expires_at, completed_at`

func scanAttempt(row interface {
	Scan(dest ...any) error
}) (*models.AuthAttempt, error) {
	var a models.AuthAttempt
	var linkToken, activeState, failureKind sql.NullString
	var sessionID uuid.NullUUID
	var completed sql.NullTime
	err := row.Scan(
		&a.ID, &a.Kind, &a.TenantID, &a.IDPID, &a.ReturnTo, &linkToken, &sessionID,
		&a.Status, &a.Recoverable, &a.Attempts, &a.MaxAttempts, &a.RecoverGeneration,
		&activeState, &failureKind, &a.RecoveryTokenHash, &a.CreatedAt, &a.UpdatedAt,
		&a.ExpiresAt, &completed)
	if err != nil {
		return nil, mapErr(err)
	}
	a.LinkToken = models.NullString{String: linkToken.String, Valid: linkToken.Valid}
	a.ActiveState = models.NullString{String: activeState.String, Valid: activeState.Valid}
	a.LastFailureKind = models.NullString{String: failureKind.String, Valid: failureKind.Valid}
	if sessionID.Valid {
		id := sessionID.UUID
		a.SessionID = &id
	}
	a.CompletedAt = models.NullTime{Time: completed.Time, Valid: completed.Valid}
	return &a, nil
}

// AttemptByID 按主键读取认证意图。
func (s *Store) AttemptByID(ctx context.Context, id uuid.UUID) (*models.AuthAttempt, error) {
	return scanAttempt(s.pool.QueryRow(ctx,
		`SELECT `+attemptColumns+` FROM auth_attempts WHERE id = $1`, id))
}

// AttemptByRecoveryHash 按恢复令牌哈希读取认证意图。
// 仅持有者拥有令牌原文（HttpOnly cookie 或 API 返回值），
// 与未知令牌相关的存在性区分在 HTTP 层统一收敛为 invalid_request。
func (s *Store) AttemptByRecoveryHash(ctx context.Context, hash []byte) (*models.AuthAttempt, error) {
	return scanAttempt(s.pool.QueryRow(ctx,
		`SELECT `+attemptColumns+` FROM auth_attempts WHERE recovery_token_hash = $1`, hash))
}

// AttemptMustBePending 供回调在触碰成员/关联逻辑前确认意图尚未终态。
// 旧请求即便越过 state 消费环节（恢复竞态等），也会在这里被挡下。
func (s *Store) AttemptMustBePending(ctx context.Context, id uuid.UUID) (*models.AuthAttempt, error) {
	a, err := s.AttemptByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if a.Status != models.AttemptPending {
		return nil, ErrAttemptTerminal
	}
	return a, nil
}

// RecordAttemptTemporaryFailure 记录一次“明确的暂时性提供方错误”：
// 意图保持 pending 但置为可恢复、摘除当前 active 请求。
// 只有 status 仍为 pending 的行可被更新 —— 已经成功的流程不会被回退。
func (s *Store) RecordAttemptTemporaryFailure(ctx context.Context, id uuid.UUID, kind string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth_attempts
		 SET recoverable = true, active_state = NULL, last_failure_kind = $2,
		     updated_at = now()
		 WHERE id = $1 AND status = 'pending'`,
		id, kind)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrAttemptTerminal
	}
	return nil
}

// RecordAttemptPermanentFailure 记录永久失败（签名/nonce/PKCE/受众/非法码等）：
// 意图终态化，绝不允许恢复。同样以 pending 为条件，防止终态回退。
func (s *Store) RecordAttemptPermanentFailure(ctx context.Context, id uuid.UUID, kind string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth_attempts
		 SET status = 'failed_permanent', recoverable = false, active_state = NULL,
		     last_failure_kind = $2, completed_at = now(), updated_at = now()
		 WHERE id = $1 AND status = 'pending'`,
		id, kind)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrAttemptTerminal
	}
	return nil
}

// MarkAttemptSucceeded 把意图条件终态化为 succeeded。
// 0 行说明它已进入其他终态（迟到回调/并发恢复竞态），调用方必须按冲突处理，
// 绝不能继续创建会话或绑定身份。
func (s *Store) MarkAttemptSucceeded(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth_attempts
		 SET status = 'succeeded', recoverable = false, active_state = NULL,
		     completed_at = now(), updated_at = now()
		 WHERE id = $1 AND status = 'pending'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrAttemptTerminal
	}
	return nil
}

// RecoverInput 是恢复一次意图所需的输入。
type RecoverInput struct {
	RecoveryTokenHash []byte
	// SessionID 为当前调用方会话：链接意图必须与发起会话逐字节一致；
	// 登录意图（无会话绑定）传 nil。
	SessionID                   *uuid.UUID
	NewState, NewNonce, NewPKCE string
}

// RecoverOutput 返回恢复结果：Reused=true 表示已存在有效后继（重复恢复/
// 双击的幂等路径），直接复用其 state/nonce/PKCE，不产生新行。
type RecoverOutput struct {
	Attempt            *models.AuthAttempt
	Reused             bool
	State, Nonce, PKCE string
}

// RecoverAttempt 是整个能力的核心原语，全部判定在单事务内完成：
//
//	锁定意图行 -> 校验会话绑定/终态/过期（链接还校验关联会话未过期）
//	-> 已有有效后继则幂等复用
//	-> 否则检查重试预算 -> 失效全部旧请求 -> 写入全新请求
//	-> 链接场景原子替换 link_sessions.b_state。
//
// 并发安全：调用前先在事务外快照 recover_generation；事务持锁后若发现代数
// 已被另一个恢复请求推进，说明后继已由它创建 —— 本事务回滚自己的插入意图，
// 转而复用那个后继，保证任何时刻只有一个有效具体请求。
func (s *Store) RecoverAttempt(ctx context.Context, in *RecoverInput) (*RecoverOutput, error) {
	// 事务外读取代数快照（FOR UPDATE 不能在事务外）。代数只在恢复创建后继时
	// 单调递增，因此“快照值 == 锁定后值”等价于“自我之后没有别人创建过后继”。
	var genSnapshot int
	row := s.pool.QueryRow(ctx,
		`SELECT recover_generation FROM auth_attempts WHERE recovery_token_hash = $1`,
		in.RecoveryTokenHash)
	if err := row.Scan(&genSnapshot); err != nil {
		return nil, mapErr(err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	a, err := scanAttempt(tx.QueryRow(ctx,
		`SELECT `+attemptColumns+` FROM auth_attempts
		 WHERE recovery_token_hash = $1 FOR UPDATE`, in.RecoveryTokenHash))
	if err != nil {
		return nil, err
	}

	// 会话绑定：链接意图必须由发起它的同一个会话恢复；登录意图无绑定。
	if a.SessionID != nil {
		if in.SessionID == nil || *in.SessionID != *a.SessionID {
			return nil, ErrConflict
		}
	}
	if a.Status != models.AttemptPending {
		return nil, ErrAttemptTerminal
	}
	now := time.Now()
	if !a.ExpiresAt.After(now) {
		if err := terminalizeInTx(tx, ctx, a.ID, models.AttemptExpired); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrAttemptExpired
	}
	// 链接场景：关联上下文必须仍然 pending 且未过期 —— 已过期关联绝不重开。
	if a.LinkToken.Valid {
		var linkStatus string
		var linkExpires time.Time
		err := tx.QueryRow(ctx,
			`SELECT status, expires_at FROM link_sessions WHERE token = $1 FOR UPDATE`,
			a.LinkToken.String,
		).Scan(&linkStatus, &linkExpires)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAttemptTerminal
		}
		if err != nil {
			return nil, err
		}
		if linkStatus != "pending" || !linkExpires.After(now) {
			if err := terminalizeInTx(tx, ctx, a.ID, models.AttemptExpired); err != nil {
				return nil, err
			}
			if err := tx.Commit(ctx); err != nil {
				return nil, err
			}
			return nil, ErrAttemptExpired
		}
	}

	var genNow int
	if err := tx.QueryRow(ctx,
		`SELECT recover_generation FROM auth_attempts WHERE id = $1`, a.ID,
	).Scan(&genNow); err != nil {
		return nil, err
	}

	// 已有有效后继（主动点恢复、双击、刷新恢复入口，或并发中别人已创建）：
	// 幂等复用，绝不生成第二个具体请求。
	if a.ActiveState.Valid && a.ActiveState.String != "" && genNow == genSnapshot {
		if ar, gerr := getActiveRequest(tx, ctx, a.ID, a.ActiveState.String); gerr == nil {
			if err := tx.Commit(ctx); err != nil {
				return nil, err
			}
			return &RecoverOutput{
				Attempt: a, Reused: true,
				State: ar.State, Nonce: ar.Nonce, PKCE: ar.PKCEVerifier,
			}, nil
		}
	}

	// 走到这里意味着需要创建后继。若代数已被并发恢复推进，则后继已经存在 ——
	// 复用它，而不是再插一行（这是“只留下一个有效后继”的关键闸门）。
	if genNow != genSnapshot {
		var curState string
		if err := tx.QueryRow(ctx,
			`SELECT active_state FROM auth_attempts WHERE id = $1`, a.ID,
		).Scan(&curState); err != nil {
			return nil, err
		}
		ar, gerr := getActiveRequest(tx, ctx, a.ID, curState)
		if gerr != nil {
			// 极端竞态：并发后继也已被消费（其回调抢先成功）。按终态处理。
			return nil, ErrAttemptTerminal
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &RecoverOutput{
			Attempt: a, Reused: true,
			State: ar.State, Nonce: ar.Nonce, PKCE: ar.PKCEVerifier,
		}, nil
	}

	// 没有有效后继且没有并发恢复：只允许从“明确的暂时性失败”恢复。
	if !a.Recoverable {
		return nil, ErrAttemptTerminal
	}
	if a.Attempts >= a.MaxAttempts {
		if err := terminalizeInTx(tx, ctx, a.ID, models.AttemptExhausted); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrAttemptExhausted
	}

	// 旧请求永久失效（消费过的自然不再有效；此语句兜底标记任何在途行）。
	if _, err := tx.Exec(ctx,
		`UPDATE auth_requests SET invalidated_at = now()
		 WHERE attempt_id = $1 AND invalidated_at IS NULL AND consumed_at IS NULL`,
		a.ID); err != nil {
		return nil, err
	}

	var linkToken, sessionID any
	if a.LinkToken.Valid {
		linkToken = a.LinkToken.String
	}
	if a.SessionID != nil {
		sessionID = *a.SessionID
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO auth_requests
		 (state, kind, tenant_id, idp_id, attempt_id, nonce, pkce_verifier,
		  return_to, link_token, session_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		in.NewState, a.Kind, a.TenantID, a.IDPID, a.ID, in.NewNonce, in.NewPKCE,
		a.ReturnTo, linkToken, sessionID); err != nil {
		return nil, mapErr(err)
	}
	// 原子推进代数 + 计数 + 指向新后继。
	if tag, err := tx.Exec(ctx,
		`UPDATE auth_attempts
		 SET attempts = attempts + 1, active_state = $2, recoverable = false,
		     recover_generation = recover_generation + 1, updated_at = now()
		 WHERE id = $1 AND status = 'pending' AND recover_generation = $3`,
		a.ID, in.NewState, genSnapshot); err != nil {
		return nil, err
	} else if tag.RowsAffected() != 1 {
		// 并发恢复已推进代数：绝不能双写。
		return nil, ErrConflict
	}
	if a.LinkToken.Valid {
		// 关联会话改绑新 state：仍然绑定原成员/租户/目标 IdP，只是换具体请求。
		tag, err := tx.Exec(ctx,
			`UPDATE link_sessions SET b_state = $2
			 WHERE token = $1 AND status = 'pending' AND expires_at > now()`,
			a.LinkToken.String, in.NewState)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrAttemptExpired
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	got, err := s.AttemptByID(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	return &RecoverOutput{
		Attempt: got, Reused: false,
		State: in.NewState, Nonce: in.NewNonce, PKCE: in.NewPKCE,
	}, nil
}

func getActiveRequest(tx pgx.Tx, ctx context.Context,
	attemptID uuid.UUID, state string) (*models.AuthRequest, error) {
	var ar models.AuthRequest
	err := tx.QueryRow(ctx,
		`SELECT state, kind, tenant_id, idp_id, attempt_id, nonce, pkce_verifier,
		        return_to, link_token, session_id, created_at
		 FROM auth_requests
		 WHERE attempt_id = $1 AND state = $2
		   AND consumed_at IS NULL AND invalidated_at IS NULL`,
		attemptID, state,
	).Scan(&ar.State, &ar.Kind, &ar.TenantID, &ar.IDPID, &ar.AttemptID, &ar.Nonce,
		&ar.PKCEVerifier, &ar.ReturnTo, &ar.LinkToken, &ar.SessionID, &ar.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConsumed
	}
	if err != nil {
		return nil, err
	}
	return &ar, nil
}

func terminalizeInTx(tx pgx.Tx, ctx context.Context, id uuid.UUID, status string) error {
	_, err := tx.Exec(ctx,
		`UPDATE auth_attempts
		 SET status = $2, recoverable = false, active_state = NULL,
		     completed_at = now(), updated_at = now()
		 WHERE id = $1 AND status = 'pending'`, id, status)
	return err
}

// ExpirePendingAttempts 把所有到期的 pending 意图标记为终态 expired。
// 进程重启后由清理循环调用：未过期意图可继续恢复，过期意图不可重开。
func (s *Store) ExpirePendingAttempts(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth_attempts
		 SET status = 'expired', active_state = NULL,
		     completed_at = now(), updated_at = now()
		 WHERE status = 'pending' AND expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteSettledAttempts 物理清理已进入终态且超过保留期的意图
// （auth_requests 随外键级联删除），防止表无限增长。
func (s *Store) DeleteSettledAttempts(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM auth_attempts
		 WHERE status <> 'pending' AND updated_at < $1`, before)
	return err
}
