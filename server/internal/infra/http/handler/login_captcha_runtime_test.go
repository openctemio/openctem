package handler

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// switchableCaptcha is a CAPTCHA whose keys can be removed at runtime (the
// console setting).
type switchableCaptcha struct{ on bool }

func (c *switchableCaptcha) Verify(context.Context, string, string) (bool, error) { return false, nil }
func (c *switchableCaptcha) Active(context.Context) bool                          { return c.on }

// A CAPTCHA set in the console is asked only while keys are configured, and
// from the moment they are, without a restart.
func TestCaptchaFollowsRuntimeKeys(t *testing.T) {
	ctx := context.Background()
	c := &switchableCaptcha{}
	f := NewMemoryLoginFailures()
	for i := 0; i < LoginCaptchaAfter; i++ {
		_ = f.Record(ctx, "198.51.100.7")
	}
	if captchaNeeded(ctx, c, f, "198.51.100.7", logger.NewNop()) {
		t.Fatal("no keys configured: the CAPTCHA must not be asked")
	}
	c.on = true
	if !captchaNeeded(ctx, c, f, "198.51.100.7", logger.NewNop()) {
		t.Fatal("keys configured: the CAPTCHA must be asked after repeated failures")
	}
	if captchaOn(ctx, nil) {
		t.Fatal("no CAPTCHA wired")
	}
}
