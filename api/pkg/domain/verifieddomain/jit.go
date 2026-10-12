package verifieddomain

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Per-domain just-in-time provisioning (RFC-058).

// JIT returns whether SSO may admit new people on this domain, and the role
// they get ("" = the identity provider's default).
func (d *VerifiedDomain) JIT() (enabled bool, role string) {
	return !d.jitDisabled, d.jitRole
}

// ChangeJIT changes the domain's just-in-time provisioning. role is "",
// "viewer" or "member": administrators are never provisioned.
func (d *VerifiedDomain) ChangeJIT(enabled bool, role string) error {
	role = strings.ToLower(strings.TrimSpace(role))
	if role != "" && role != "viewer" && role != "member" {
		return fmt.Errorf("%w: jit_role must be viewer or member", shared.ErrValidation)
	}
	d.jitDisabled = !enabled
	d.jitRole = role
	return nil
}

// WithJIT restores the JIT settings from persistence.
func (d *VerifiedDomain) WithJIT(enabled bool, role string) *VerifiedDomain {
	d.jitDisabled = !enabled
	d.jitRole = role
	return d
}
