package scope

// Authorization source of a scope entry (RFC-065 §4): why the entry
// authorizes probes. The one authority check is the same for every source;
// the source decides how an entry comes into effect and where its traffic
// may come from.

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AuthorizationSource is why a scope entry authorizes probes.
type AuthorizationSource string

// Authorization sources.
const (
	// AuthOwnership: the organization's own estate (the default).
	AuthOwnership AuthorizationSource = "ownership"
	// AuthProgram: a bug-bounty program's published scope; created only by
	// the programs service, with the importer's attestation.
	AuthProgram AuthorizationSource = "program"
	// AuthLetter: a signed letter of authorization (P1).
	AuthLetter AuthorizationSource = "authorization_letter"
	// AuthSelfAttestation: an internal or on-premises statement; approved
	// as ownership entries are.
	AuthSelfAttestation AuthorizationSource = "self_attestation"
)

// Valid reports whether s is a known source.
func (s AuthorizationSource) Valid() bool {
	switch s {
	case AuthOwnership, AuthProgram, AuthLetter, AuthSelfAttestation:
		return true
	}
	return false
}

// ErrProgramEntryViaPrograms refuses a program entry on the general routes.
var ErrProgramEntryViaPrograms = shared.NewDomainError("PROGRAM_ENTRY_VIA_PROGRAMS",
	"program entries are created by importing the program (Programs), not on the Scope page", shared.ErrValidation)

// ErrProgramManaged refuses widening a program entry outside its program.
var ErrProgramManaged = shared.NewDomainError("PROGRAM_MANAGED",
	"this entry belongs to a program; change it by re-importing or resuming the program", shared.ErrConflict)

// ParseGeneralSource reads the source a person may choose on the general
// scope routes: ownership (default) or self_attestation. Program entries
// come only from the programs service; letters arrive in a later phase.
func ParseGeneralSource(s string) (AuthorizationSource, error) {
	switch AuthorizationSource(s) {
	case "", AuthOwnership:
		return AuthOwnership, nil
	case AuthSelfAttestation:
		return AuthSelfAttestation, nil
	case AuthProgram:
		return "", ErrProgramEntryViaPrograms
	}
	return "", fmt.Errorf("%w: authorization_source must be ownership or self_attestation", shared.ErrValidation)
}

// AuthorizationSource is why the entry authorizes probes (ownership when
// unset).
func (t *Target) AuthorizationSource() AuthorizationSource {
	if t.authSource == "" {
		return AuthOwnership
	}
	return t.authSource
}

// ProgramID is the program a program entry belongs to (nil otherwise).
func (t *Target) ProgramID() *shared.ID { return t.programID }

// IsProgramEntry reports whether the entry comes from a program.
func (t *Target) IsProgramEntry() bool { return t.AuthorizationSource() == AuthProgram }

// SetAuthorization sets the source and, for a program entry, its program.
// A program entry needs a program; no other source has one.
func (t *Target) SetAuthorization(s AuthorizationSource, programID *shared.ID) error {
	switch {
	case !s.Valid():
		return fmt.Errorf("%w: unknown authorization source", shared.ErrValidation)
	case (s == AuthProgram) != (programID != nil && !programID.IsZero()):
		return fmt.Errorf("%w: a program entry needs its program, and only a program entry has one", shared.ErrValidation)
	}
	t.authSource = s
	if s == AuthProgram {
		id := *programID
		t.programID = &id
		t.origin = OriginProgram
	} else {
		t.programID = nil
	}
	return nil
}
