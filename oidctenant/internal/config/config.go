// Package config 读取进程环境配置。
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string
	// BaseURL 是本应用对外可达地址，回调路径固定为 /oauth/callback。
	BaseURL string
	Addr    string

	SessionTTL     time.Duration
	LinkTTL        time.Duration
	AuthRequestTTL time.Duration
	// AttemptMaxRetries 是一次认证意图允许的最大恢复次数（不含首次请求）。
	AttemptMaxRetries int
	CookieSecure      bool
	CookieSameSite    string
	CleanupInterval   time.Duration
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		BaseURL:           strings.TrimRight(getenv("BASE_URL", "http://localhost:8080"), "/"),
		Addr:              getenv("ADDR", ":8080"),
		SessionTTL:        8 * time.Hour,
		LinkTTL:           10 * time.Minute,
		AuthRequestTTL:    10 * time.Minute,
		AttemptMaxRetries: 3,
		CookieSecure:      os.Getenv("COOKIE_SECURE") == "true",
		CookieSameSite:    getenv("COOKIE_SAMESITE", "lax"),
		CleanupInterval:   time.Minute,
	}
	if v := strings.TrimSpace(os.Getenv("ATTEMPT_MAX_RETRIES")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 20 {
			return nil, fmt.Errorf("ATTEMPT_MAX_RETRIES must be an integer between 0 and 20")
		}
		cfg.AttemptMaxRetries = n
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("BASE_URL is required")
	}
	return cfg, nil
}
