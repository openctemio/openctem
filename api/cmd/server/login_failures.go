package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// redisLoginFailures counts failed sign-ins per client address across
// replicas: a window of handler.LoginFailureWindow holding up to
// handler.LoginCaptchaAfter hits.
type redisLoginFailures struct{ rl *redis.RateLimiter }

func newLoginFailureCounter(client *redis.Client, log *logger.Logger) handler.LoginFailureCounter {
	if client != nil {
		if rl, err := redis.NewRateLimiter(client, "login_failures", handler.LoginCaptchaAfter, handler.LoginFailureWindow, log); err == nil {
			return redisLoginFailures{rl: rl}
		}
	}
	return handler.NewMemoryLoginFailures()
}

func (r redisLoginFailures) Failures(ctx context.Context, key string) (int, error) {
	st, err := r.rl.Status(ctx, key)
	if err != nil {
		return 0, err
	}
	return r.rl.Limit() - st.Remaining, nil
}

func (r redisLoginFailures) Record(ctx context.Context, key string) error {
	_, err := r.rl.Allow(ctx, key)
	return err
}

func (r redisLoginFailures) Reset(ctx context.Context, key string) error { return r.rl.Reset(ctx, key) }
