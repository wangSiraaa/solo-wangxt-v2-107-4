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

// 尝试状态取值（auth_attempts.status）。
const (
	AttemptPending         = "pending"
	AttemptSucceeded       = "succeeded"
	AttemptFailedPermanent = "failed_permanent"
	AttemptExpired         = "expired"
	AttemptExhausted       = "exhausted"
)

// AuthAttempt 表示一次用户认证意图（普通登录或账号关联）。
// 意图与具体 OIDC 请求分离：暂时性失败后可在同一意图下派生全新请求，
// 但每个具体请求（state/nonce/PKCE）仍是一次性、且只能有一个有效。
type AuthAttempt struct {
	ID                uuid.UUID
	Kind              string
	TenantID          uuid.UUID
	IDPID             uuid.UUID
	ReturnTo          string
	LinkToken         NullString
	SessionID         *uuid.UUID
	Status            string
	Recoverable       bool
	Attempts          int
	MaxAttempts       int
	RecoverGeneration int
	ActiveState       NullString
	LastFailureKind   NullString
	RecoveryTokenHash []byte
	CreatedAt         time.Time
	UpdatedAt         time.Time
	ExpiresAt         time.Time
	CompletedAt       NullTime
}

type AuthRequest struct {
	State        string
	Kind         string
	TenantID     uuid.UUID
	IDPID        uuid.UUID
	AttemptID    uuid.UUID
	Nonce        string
	PKCEVerifier string
	ReturnTo     string
	LinkToken    NullString
	SessionID    *uuid.UUID
	CreatedAt    time.Time
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
	Status         string
	ExpiresAt      time.Time
}
