package integration

import (
	"context"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// dbHolder 由 *testEnv 与 *recoverEnv 共同实现。
type dbHolder interface {
	DB() *pgxpool.Pool
}

func countRows(t *testing.T, env dbHolder, query string, args ...any) int {
	t.Helper()
	var n int
	if err := env.DB().QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("countRows: %v (query=%s)", err, query)
	}
	return n
}

func ioReadAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	return io.ReadAll(r)
}
