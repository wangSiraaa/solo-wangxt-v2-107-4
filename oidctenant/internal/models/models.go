// Package models 定义持久化层的数据结构。
package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// NullString / NullTime 复用标准库可空标量类型，便于 pgx 直接互操作。
type (
	NullString = sql.NullString
	NullTime   = sql.NullTime
)

type Tenant struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	CreatedAt time.Time
}

type Provider struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	Issuer         string
	ClientID       string
	ClientSecret   string
	RedirectURIs   []string
	AuthTimeMaxAge int
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Member struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	DisplayName string
	CreatedAt   time.Time
}

type Identity struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	MemberID      uuid.UUID
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
}

type AuthRequest struct {
	State        string
	Kind         string
	TenantID     uuid.UUID
	IDPID        uuid.UUID
	Nonce        string
	PKCEVerifier string
	ReturnTo     string
	LinkToken    NullString
	SessionID    *uuid.UUID
	CreatedAt    time.Time
	// AttemptID 关联本次请求所属的用户意图；RequestSeq 为代次（首次为 1）。
	AttemptID  *uuid.UUID
	RequestSeq int
}

// AuthAttempt 是一次用户认证意图（登录或关联），跨多次具体 OIDC 请求存活。
// 每个 attempt 同时至多有一个未消费的具体请求（auth_requests 部分唯一索引保证）。
type AuthAttempt struct {
	ID                     uuid.UUID
	Token                  string
	Kind                   string
	TenantID               uuid.UUID
	IDPID                  uuid.UUID
	ReturnTo               string
	LinkToken              NullString
	SessionID              *uuid.UUID
	Status                 string
	RequestSeq             int
	MaxRetries             int
	LastFailureKind        NullString
	LastFailureRecoverable bool
	LastFailureAt          NullTime
	// FailedRequestSeq 是最近一次失败所属的具体请求代次（0 表示尚无失败）。
	FailedRequestSeq int
	CreatedAt        time.Time
	ExpiresAt        time.Time
	FinishedAt       NullTime
}

type Session struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	MemberID  uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
}

type LinkSession struct {
	Token          string
	TenantID       uuid.UUID
	AnchorMemberID uuid.UUID
	SessionID      uuid.UUID
	TargetIDPID    uuid.UUID
	AIssuer        string
	ASubject       string
	AAuthTime      NullTime
	BIssuer        string
	BSubject       string
	BEmail         string
	BAuthTime      NullTime
	BIDPID         uuid.UUID
	BState         string
	BAttemptID     *uuid.UUID
	Status         string
	ExpiresAt      time.Time
}
