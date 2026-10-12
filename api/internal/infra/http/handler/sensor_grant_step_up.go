package handler

// Step-up re-authentication for widening a sensor's grant
// (docs/architecture/step-up-reauth.md). Narrowing stays one click, so the
// check runs only where the grant service knows the change widens.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// StepUpWideningApprover approves a widening only when the caller's session
// signed in or stepped up within window. It fails closed.
type StepUpWideningApprover struct {
	Checker middleware.RecentAuthChecker
	Window  time.Duration
}

var _ sensorgrant.WideningApprover = StepUpWideningApprover{}

// ApproveWidening implements sensorgrant.WideningApprover.
func (a StepUpWideningApprover) ApproveWidening(ctx context.Context, _ sensorgrant.Actor, _, _ sensordom.Grant, _ []string) error {
	return middleware.CheckRecentAuth(ctx, a.Checker, a.Window)
}
