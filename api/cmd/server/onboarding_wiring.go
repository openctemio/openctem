package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	onboardingapp "github.com/openctemio/openctem/api/internal/app/onboarding"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// onboardingTenants adapts the tenant service to the onboarding port.
type onboardingTenants struct{ *tenantapp.TenantService }

func (t onboardingTenants) AddMember(ctx context.Context, tenantID string, in onboardingapp.AddMemberInput, inviter shared.ID, actx auditapp.AuditContext) (*tenantdom.Membership, error) {
	return t.TenantService.AddMember(ctx, tenantID, tenantapp.AddMemberInput{UserID: in.UserID, Role: in.Role}, inviter, actx)
}

// deriveKey derives a purpose-bound key from a server secret, so the
// onboarding offer key is never the session signing key itself.
func deriveKey(secret, label string) []byte {
	if secret == "" {
		return nil
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(label))
	return h.Sum(nil)
}
