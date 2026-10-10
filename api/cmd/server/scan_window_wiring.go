package main

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/internal/app/auth"
	scanwindowapp "github.com/openctemio/openctem/api/internal/app/scanwindow"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// scanWindowTOTP is the fresh authenticator check of a scan window override
// (RFC-067 §8), in the scan window service's error terms.
type scanWindowTOTP struct{ auth *auth.AuthService }

var _ scanwindowapp.TOTPVerifier = scanWindowTOTP{}

func (v scanWindowTOTP) VerifyFreshTOTP(ctx context.Context, userID, code string) error {
	err := v.auth.VerifyFreshTOTP(ctx, userID, code)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, auth.ErrTOTPNotEnrolled):
		return swdom.ErrOverrideNeedsTOTP
	case errors.Is(err, auth.ErrStepUpFailed), errors.Is(err, auth.ErrAccountLocked):
		return swdom.ErrOverrideBadCode
	}
	return err
}

// wireScanWindowTOTP gives the scan window service the authenticator check;
// without it every override is refused.
func wireScanWindowTOTP(svc *Services) {
	if svc.ScanWindow != nil && svc.Auth != nil {
		svc.ScanWindow.SetTOTP(scanWindowTOTP{auth: svc.Auth})
	}
}

// newScanWindowHandler is nil when scan windows are not wired.
func newScanWindowHandler(svc *Services, log *logger.Logger) *handler.ScanWindowHandler {
	if svc.ScanWindow == nil {
		return nil
	}
	return handler.NewScanWindowHandler(svc.ScanWindow, log)
}
