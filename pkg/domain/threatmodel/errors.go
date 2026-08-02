// Package threatmodel holds the domain model for Continuous Threat Modeling —
// a live, per-scope threat model that is derived (never drawn) from attacker
// profiles × exposure chains × applicable ATT&CK techniques, with every threat's
// status derived from live findings/validation.
//
// See docs/rfcs/RFC-continuous-threat-modeling.md.
package threatmodel

import "github.com/openctemio/api/pkg/domain/shared"

// Domain errors.
var (
	// ErrNotFound is returned when a threat model does not exist for the tenant.
	ErrNotFound = shared.NewDomainError("THREAT_MODEL_NOT_FOUND", "threat model not found", shared.ErrNotFound)
	// ErrInvalidScope is returned when scope_type is not a recognized value.
	ErrInvalidScope = shared.NewDomainError("THREAT_MODEL_INVALID_SCOPE", "invalid threat model scope type", shared.ErrValidation)
	// ErrInvalidStatus is returned when a threat status is not a recognized value.
	ErrInvalidStatus = shared.NewDomainError("THREAT_MODEL_INVALID_STATUS", "invalid threat status", shared.ErrValidation)
	// ErrEmptyName is returned when a threat model is created without a name.
	ErrEmptyName = shared.NewDomainError("THREAT_MODEL_EMPTY_NAME", "threat model name is required", shared.ErrValidation)
)
