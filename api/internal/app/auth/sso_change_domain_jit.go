package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// Per-domain just-in-time provisioning from the admin console (RFC-058).
//
// Lowering it (no newcomers, or a lower role) removes a way in and applies
// at once. Raising it (admitting newcomers, or a higher role) gives people
// privileges in the organization, so it waits for an owner like any other
// SSO change; an organization without an owner yet (bootstrap) applies it
// directly.

// DomainJITStore reads and changes a verified domain's provisioning.
type DomainJITStore interface {
	GetDomain(ctx context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error)
	ChangeJIT(ctx context.Context, tenantID, id shared.ID, enabled bool, role string) (*verifieddomain.VerifiedDomain, error)
}

// SetDomainJITStore wires the verified domains (domainverify.Service).
func (s *SSOChangeService) SetDomainJITStore(d DomainJITStore) { s.domains = d }

// DomainJITPayload is a proposed per-domain provisioning.
type DomainJITPayload struct {
	Domain     string `json:"domain"`
	JITEnabled bool   `json:"jit_enabled"`
	JITRole    string `json:"jit_role"`
}

// jitLevel orders provisioning settings: off < viewer < identity-provider
// default < member. The default may be member, so it ranks above viewer.
func jitLevel(enabled bool, role string) int {
	switch {
	case !enabled:
		return 0
	case role == "viewer":
		return 1
	case role == "":
		return 2
	default:
		return 3
	}
}

// JITRaises reports whether moving from (oldOn, oldRole) to (on, role)
// admits more people or gives them more.
func JITRaises(oldOn bool, oldRole string, on bool, role string) bool {
	return jitLevel(on, role) > jitLevel(oldOn, oldRole)
}

// SubmitDomainJIT changes a domain's provisioning: directly when it lowers
// it (or the organization has no owner yet), otherwise as a pending change
// for an owner.
func (s *SSOChangeService) SubmitDomainJIT(ctx context.Context, tenantID, id shared.ID, enabled bool, role string, by SSOChangeRequester) (*SSOChangeResult, *verifieddomain.VerifiedDomain, error) {
	if s.domains == nil {
		return nil, nil, fmt.Errorf("%w: verified domains are not configured", shared.ErrValidation)
	}
	vd, err := s.domains.GetDomain(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	// Validate the new values on a copy before deciding.
	proposed := *vd
	if err := proposed.ChangeJIT(enabled, role); err != nil {
		return nil, nil, err
	}
	oldOn, oldRole := vd.JIT()
	newOn, newRole := proposed.JIT()
	pending := false
	if JITRaises(oldOn, oldRole, newOn, newRole) {
		if pending, err = s.needsApproval(ctx, tenantID); err != nil {
			return nil, nil, err
		}
	}
	if !pending {
		applied, err := s.domains.ChangeJIT(ctx, tenantID, id, newOn, newRole)
		if err != nil {
			return nil, nil, err
		}
		return &SSOChangeResult{Applied: true}, applied, nil
	}
	res, err := s.store(ctx, tenantID, ssochange.KindDomainJIT, id.String(),
		DomainJITPayload{Domain: vd.Domain(), JITEnabled: newOn, JITRole: newRole}, "", by)
	return res, nil, err
}

func (s *SSOChangeService) domainJITWrite(ctx context.Context, c *ssochange.Change) (ssochange.LiveWrite, error) {
	var p DomainJITPayload
	if err := json.Unmarshal(c.Payload, &p); err != nil {
		return ssochange.LiveWrite{}, fmt.Errorf("decode domain change: %w", err)
	}
	if s.domains == nil {
		return ssochange.LiveWrite{}, fmt.Errorf("%w: verified domains are not configured", shared.ErrValidation)
	}
	id, err := shared.IDFromString(c.TargetID)
	if err != nil {
		return ssochange.LiveWrite{}, verifieddomain.ErrNotFound
	}
	vd, err := s.domains.GetDomain(ctx, c.TenantID, id)
	if err != nil {
		return ssochange.LiveWrite{}, err
	}
	if err := vd.ChangeJIT(p.JITEnabled, p.JITRole); err != nil {
		return ssochange.LiveWrite{}, err
	}
	return ssochange.LiveWrite{DomainJIT: vd}, nil
}

func describeDomainJIT(c *ssochange.Change) string {
	var p DomainJITPayload
	_ = json.Unmarshal(c.Payload, &p)
	if !p.JITEnabled {
		return fmt.Sprintf("stop admitting new people on %s", p.Domain)
	}
	role := p.JITRole
	if role == "" {
		role = "the identity provider's default role"
	}
	return fmt.Sprintf("let the organization's SSO admit new people on %s as %s", p.Domain, role)
}
