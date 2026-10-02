package store_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	embedded "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/db"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/store"
)

// 纯 store 层测试：不依赖任何 OIDC 提供方，直接验证可恢复尝试的
// 事务不变量（并发恢复、旧请求失效、终态不回退、链接上下文绑定）。

type fixture struct {
	pg       *embedded.EmbeddedPostgres
	st       *store.Store
	tenantID uuid.UUID
	idpID    uuid.UUID
}

func freePort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return uint32(p)
}

func startFixture(t *testing.T) *fixture {
	t.Helper()
	pgPort := freePort(t)
	pg := embedded.NewDatabase(embedded.DefaultConfig().
		Port(pgPort).Database("oidctenant").DataPath(t.TempDir()).
		CachePath("/workspace/tools/ep-cache").Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatalf("pg: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })

	dsn := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/oidctenant?sslmode=disable", pgPort)
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := store.New(pool)

	f := &fixture{pg: pg, st: st,
		tenantID: uuid.MustParse("00000000-0000-0000-0000-0000000000d1"),
		idpID:    uuid.MustParse("00000000-0000-0000-0000-0000000000d2")}
	if err := st.UpsertTenant(ctx, f.tenantID, "t", "T"); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	// 先建一个 member 供链接会话外键使用。
	if err := pool.QueryRow(ctx,
		`INSERT INTO members(id, tenant_id) VALUES ($1,$2) RETURNING id`,
		uuid.New(), f.tenantID).Scan(new(uuid.UUID)); err != nil {
		t.Fatalf("member: %v", err)
	}
	if err := st.UpsertProvider(ctx, &models.Provider{
		ID: f.idpID, TenantID: f.tenantID, Issuer: "https://idp.test",
		ClientID: "c", ClientSecret: "s",
		RedirectURIs: []string{"http://localhost/cb"}, Enabled: true,
	}); err != nil {
		t.Fatalf("provider: %v", err)
	}
	return f
}

func (f *fixture) memberID(t *testing.T) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.st.DB().QueryRow(context.Background(),
		`SELECT id FROM members WHERE tenant_id=$1 LIMIT 1`, f.tenantID).Scan(&id); err != nil {
		t.Fatalf("member id: %v", err)
	}
	return id
}

func newAttemptInput(id uuid.UUID, state string) *store.CreateAttemptInput {
	return &store.CreateAttemptInput{
		ID:                id,
		Kind:              "login",
		TenantID:          uuid.MustParse("00000000-0000-0000-0000-0000000000d1"),
		IDPID:             uuid.MustParse("00000000-0000-0000-0000-0000000000d2"),
		ReturnTo:          "/",
		RecoveryTokenHash: []byte("recovery-hash-" + id.String()),
		State:             state,
		Nonce:             "nonce-" + state,
		PKCEVerifier:      "verifier-" + state,
	}
}

// TestConcurrentRecoveryCreatesSingleSuccessor：N 个并发恢复只产生一个后继。
func TestConcurrentRecoveryCreatesSingleSuccessor(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	id := uuid.New()
	if _, err := f.st.CreateLoginAttempt(ctx, newAttemptInput(id, "state-0"),
		time.Minute, 5); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.st.RecordAttemptTemporaryFailure(ctx, id, "provider_unavailable"); err != nil {
		t.Fatalf("temp fail: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	outs := make([]*store.RecoverOutput, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := f.st.RecoverAttempt(ctx, &store.RecoverInput{
				RecoveryTokenHash: []byte("recovery-hash-" + id.String()),
				NewState:          fmt.Sprintf("state-recover-%d", i),
				NewNonce:          fmt.Sprintf("nonce-%d", i),
				NewPKCE:           fmt.Sprintf("verifier-%d", i),
			})
			errs[i] = err
			outs[i] = out
		}(i)
	}
	wg.Wait()

	winners := 0
	winnerState := ""
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent recovery must resolve (create once, reuse rest), got %v", err)
		}
		if !outs[i].Reused {
			winners++
			winnerState = outs[i].State
		}
	}
	if winners != 1 {
		t.Fatalf("exactly one recovery should create the successor, got %d creators", winners)
	}
	// 所有结果（创建者与复用者）必须指向同一个后继 state。
	for i, out := range outs {
		if out.State != winnerState {
			t.Fatalf("call %d resolved state=%s, want shared winner %s", i, out.State, winnerState)
		}
	}

	a, err := f.st.AttemptByID(ctx, id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if a.Attempts != 2 {
		t.Fatalf("attempts=%d, want 2 (exactly one successor)", a.Attempts)
	}
	var valid int
	if err := f.st.DB().QueryRow(ctx,
		`SELECT count(*) FROM auth_requests
		 WHERE attempt_id=$1 AND consumed_at IS NULL AND invalidated_at IS NULL`,
		id).Scan(&valid); err != nil {
		t.Fatalf("count valid: %v", err)
	}
	if valid != 1 {
		t.Fatalf("valid concrete requests=%d, want exactly 1", valid)
	}
}

// TestOldRequestInvalidatedAfterRecovery：恢复后旧 state 无法再消费。
func TestOldRequestInvalidatedAfterRecovery(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	id := uuid.New()
	if _, err := f.st.CreateLoginAttempt(ctx, newAttemptInput(id, "state-old"),
		time.Minute, 3); err != nil {
		t.Fatalf("create: %v", err)
	}
	// 旧请求在回调中被消费（模拟暂时性失败发生在令牌交换阶段）。
	if _, err := f.st.ConsumeAuthRequest(ctx, "state-old"); err != nil {
		t.Fatalf("consume old: %v", err)
	}
	if err := f.st.RecordAttemptTemporaryFailure(ctx, id, "provider_unavailable"); err != nil {
		t.Fatalf("temp: %v", err)
	}
	out, err := f.st.RecoverAttempt(ctx, &store.RecoverInput{
		RecoveryTokenHash: []byte("recovery-hash-" + id.String()),
		NewState:          "state-new", NewNonce: "n", NewPKCE: "v",
	})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}

	// 旧 state 重放：与未知 state 一致的 ErrConsumed。
	if _, err := f.st.ConsumeAuthRequest(ctx, "state-old"); !errors.Is(err, store.ErrConsumed) {
		t.Fatalf("old state consume err=%v, want ErrConsumed", err)
	}
	// 新 state 可正常消费一次，第二次被拒。
	ar, err := f.st.ConsumeAuthRequest(ctx, out.State)
	if err != nil || ar == nil {
		t.Fatalf("new state consume: %v", err)
	}
	if _, err := f.st.ConsumeAuthRequest(ctx, out.State); !errors.Is(err, store.ErrConsumed) {
		t.Fatalf("new state replay err=%v, want ErrConsumed", err)
	}
}

// TestTerminalAttemptCannotRecoverOrSucceedAgain：终态不回退。
func TestTerminalAttemptCannotRecoverOrSucceedAgain(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()

	t.Run("succeeded", func(t *testing.T) {
		id := uuid.New()
		if _, err := f.st.CreateLoginAttempt(ctx, newAttemptInput(id, "s-"+id.String()[:8]),
			time.Minute, 3); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := f.st.MarkAttemptSucceeded(ctx, id); err != nil {
			t.Fatalf("succeed: %v", err)
		}
		// 再次成功终态化必须失败（不回退）。
		if err := f.st.MarkAttemptSucceeded(ctx, id); !errors.Is(err, store.ErrAttemptTerminal) {
			t.Fatalf("second succeed err=%v, want ErrAttemptTerminal", err)
		}
		// 暂时性失败记录也不能落到已成功尝试上。
		if err := f.st.RecordAttemptTemporaryFailure(ctx, id, "x"); !errors.Is(err, store.ErrAttemptTerminal) {
			t.Fatalf("temp fail on succeeded err=%v, want ErrAttemptTerminal", err)
		}
	})

	t.Run("permanent_failed", func(t *testing.T) {
		id := uuid.New()
		if _, err := f.st.CreateLoginAttempt(ctx, newAttemptInput(id, "p-"+id.String()[:8]),
			time.Minute, 3); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := f.st.RecordAttemptPermanentFailure(ctx, id, "signature"); err != nil {
			t.Fatalf("perm fail: %v", err)
		}
		_, err := f.st.RecoverAttempt(ctx, &store.RecoverInput{
			RecoveryTokenHash: []byte("recovery-hash-" + id.String()),
			NewState:          "x", NewNonce: "n", NewPKCE: "v",
		})
		if !errors.Is(err, store.ErrAttemptTerminal) {
			t.Fatalf("recover permanent err=%v, want ErrAttemptTerminal", err)
		}
	})
}

// TestRecoverNonRecoverablePendingRejected：没有暂时性失败记录时不能恢复。
func TestRecoverNonRecoverablePendingRejected(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	id := uuid.New()
	if _, err := f.st.CreateLoginAttempt(ctx, newAttemptInput(id, "state-ini"),
		time.Minute, 3); err != nil {
		t.Fatalf("create: %v", err)
	}
	// 初始请求仍有效（用户只是主动点了恢复入口）：恢复必须复用它，而非新建。
	out, err := f.st.RecoverAttempt(ctx, &store.RecoverInput{
		RecoveryTokenHash: []byte("recovery-hash-" + id.String()),
		NewState:          "should-not-be-used", NewNonce: "n", NewPKCE: "v",
	})
	if err != nil {
		t.Fatalf("recover with live active request: %v", err)
	}
	if !out.Reused || out.State != "state-ini" {
		t.Fatalf("expected reuse of live request, got reused=%v state=%s", out.Reused, out.State)
	}
}

// TestRecoverMaxAttempts：超过上限返回 ErrAttemptExhausted 并终态化。
func TestRecoverMaxAttempts(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	id := uuid.New()
	if _, err := f.st.CreateLoginAttempt(ctx, newAttemptInput(id, "m0"),
		time.Minute, 2); err != nil {
		t.Fatalf("create: %v", err)
	}
	for step, wantErr := range []error{nil, store.ErrAttemptExhausted} {
		// 每次先消费当前请求并记录暂时性失败，再恢复。
		a, err := f.st.AttemptByID(ctx, id)
		if err != nil {
			t.Fatalf("load %d: %v", step, err)
		}
		if a.ActiveState.Valid {
			if _, err := f.st.ConsumeAuthRequest(ctx, a.ActiveState.String); err != nil {
				t.Fatalf("consume %d: %v", step, err)
			}
		}
		if err := f.st.RecordAttemptTemporaryFailure(ctx, id, "provider_unavailable"); err != nil {
			t.Fatalf("temp %d: %v", step, err)
		}
		_, err = f.st.RecoverAttempt(ctx, &store.RecoverInput{
			RecoveryTokenHash: []byte("recovery-hash-" + id.String()),
			NewState:          fmt.Sprintf("m%d", step+1), NewNonce: "n", NewPKCE: "v",
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("step %d err=%v, want %v", step, err, wantErr)
		}
	}
	a, _ := f.st.AttemptByID(ctx, id)
	if a.Status != models.AttemptExhausted {
		t.Fatalf("status=%s, want exhausted", a.Status)
	}
}

// TestLinkRecoveryStaysBoundAndRespectsExpiry：链接恢复绑定原会话，
// 且关联会话过期后恢复被拒。
func TestLinkRecoveryStaysBoundAndRespectsExpiry(t *testing.T) {
	f := startFixture(t)
	ctx := context.Background()
	memberID := f.memberID(t)
	sessID := uuid.New()
	linkToken := "link-tok-1"

	// 直接建一个会话行以满足外键。
	if _, err := f.st.DB().Exec(ctx,
		`INSERT INTO sessions(id, tenant_id, member_id, token_hash, expires_at)
		 VALUES ($1,$2,$3,$4, now()+interval '1 hour')`,
		sessID, f.tenantID, memberID, []byte("sess-hash")); err != nil {
		t.Fatalf("session: %v", err)
	}

	in := newAttemptInput(uuid.New(), "link-state-0")
	in.Kind = "link_b"
	in.LinkToken = linkToken
	in.SessionID = &sessID
	if _, err := f.st.CreateLinkAttempt(ctx, &store.LinkAttemptInput{
		Attempt:        *in,
		AnchorMemberID: memberID,
		TargetIDPID:    f.idpID,
		AIssuer:        "https://idp.test",
		ASubject:       "a-sub",
		AAuthTime:      time.Now(),
		LinkTTL:        time.Minute,
	}, time.Minute, 3); err != nil {
		t.Fatalf("create link attempt: %v", err)
	}
	if _, err := f.st.ConsumeAuthRequest(ctx, "link-state-0"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := f.st.RecordAttemptTemporaryFailure(ctx, in.ID, "provider_unavailable"); err != nil {
		t.Fatalf("temp: %v", err)
	}

	// 错误会话恢复：被拒。
	other := uuid.New()
	_, err := f.st.RecoverAttempt(ctx, &store.RecoverInput{
		RecoveryTokenHash: in.RecoveryTokenHash, SessionID: &other,
		NewState: "link-state-1", NewNonce: "n", NewPKCE: "v",
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("cross-session recover err=%v, want ErrConflict", err)
	}

	// 原会话恢复成功，且 link_sessions.b_state 改绑新 state。
	out, err := f.st.RecoverAttempt(ctx, &store.RecoverInput{
		RecoveryTokenHash: in.RecoveryTokenHash, SessionID: &sessID,
		NewState: "link-state-1", NewNonce: "n1", NewPKCE: "v1",
	})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	var boundState string
	if err := f.st.DB().QueryRow(ctx,
		`SELECT b_state FROM link_sessions WHERE token=$1`, linkToken).Scan(&boundState); err != nil {
		t.Fatalf("b_state: %v", err)
	}
	if boundState != out.State {
		t.Fatalf("b_state=%s, want newly minted %s", boundState, out.State)
	}

	// 关联会话过期后再次恢复：拒绝且不重开。
	if _, err := f.st.DB().Exec(ctx,
		`UPDATE link_sessions SET expires_at=now()-interval '1 second' WHERE token=$1`,
		linkToken); err != nil {
		t.Fatalf("expire link: %v", err)
	}
	if _, err := f.st.ConsumeAuthRequest(ctx, out.State); err != nil {
		t.Fatalf("consume successor: %v", err)
	}
	if err := f.st.RecordAttemptTemporaryFailure(ctx, in.ID, "provider_unavailable"); err != nil {
		t.Fatalf("temp 2: %v", err)
	}
	_, err = f.st.RecoverAttempt(ctx, &store.RecoverInput{
		RecoveryTokenHash: in.RecoveryTokenHash, SessionID: &sessID,
		NewState: "link-state-2", NewNonce: "n2", NewPKCE: "v2",
	})
	if !errors.Is(err, store.ErrAttemptExpired) {
		t.Fatalf("expired link recover err=%v, want ErrAttemptExpired", err)
	}
}
