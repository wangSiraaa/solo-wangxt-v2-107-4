package integration

import (
	"context"
	"testing"
)

// countWhere 在 resumeEnv 上执行返回单个整数的查询（便于带表达式断言）。
func countWhere(t *testing.T, env *resumeEnv, query string, args ...any) int {
	t.Helper()
	var n int
	if err := env.store.DB().QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("countWhere: %v (query=%s)", err, query)
	}
	return n
}
