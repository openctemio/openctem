package handler

// Step-up re-authentication for widening a sensor's grant
// (docs/architecture/step-up-reauth.md). Narrowing stays one click, so the
// check runs only where the grant service knows the change widens.

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/stepup"
)

// StepUpWideningApprover approves a widening only when the caller
// re-authenticated as the organization's critical rule asks. It fails closed.
type StepUpWideningApprover struct {
	Checker  middleware.RecentAuthChecker
	Policies middleware.StepUpPolicyProvider
}

var _ sensorgrant.WideningApprover = StepUpWideningApprover{}

// ApproveWidening implements sensorgrant.WideningApprover.
func (a StepUpWideningApprover) ApproveWidening(ctx context.Context, _ sensorgrant.Actor, _, _ sensordom.Grant, _ []string) error {
	return middleware.CheckStepUp(ctx, a.Checker, a.Policies, stepup.TierCritical)
}
