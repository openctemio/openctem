// Package coverage is the asset coverage ledger: for each asset, capability
// and vantage, whether the capability has been done, when, with what
// outcome, and when it is due again (docs/rfcs/RFC-093-asset-coverage.md).
package coverage

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// State is the state of one (asset, capability, vantage) pair.
type State string

// States.
const (
	// StateDue: the pair needs the capability now (never done, cadence
	// elapsed, or the facts it depends on changed).
	StateDue State = "due"
	// StateQueued: work for the pair was handed to the dispatcher.
	StateQueued State = "queued"
	// StateCovered: the last attempt succeeded and is within the cadence.
	StateCovered State = "covered"
	// StateFailed: the last attempt failed; the pair is due again after a
	// back-off.
	StateFailed State = "failed"
	// StateBlocked: the scope gate, a guardrail, placement or a budget
	// refused the pair; Reason says which. Not a coverage gap.
	StateBlocked State = "blocked"
	// StatePaused: a window, a hold or a switch paused the pair.
	StatePaused State = "paused"
	// StateNotApplicable: a precondition of the rule does not hold (the name
	// does not resolve, the port is not a web port).
	StateNotApplicable State = "not_applicable"
)

// IsValid reports whether s is a known state.
func (s State) IsValid() bool {
	switch s {
	case StateDue, StateQueued, StateCovered, StateFailed, StateBlocked, StatePaused, StateNotApplicable:
		return true
	}
	return false
}

// Capabilities the platform runs itself (no stage, no sensor).
const (
	// CapabilityDNSDangling is the dangling-DNS / takeover check.
	CapabilityDNSDangling = "dns.dangling"
	// CapabilityDNSEmail is the email security (SPF, DMARC, MTA-STS) check.
	CapabilityDNSEmail = "dns.email"
	// CapabilityNetworkVAConnector is a dispatch to a vulnerability
	// assessment connector.
	CapabilityNetworkVAConnector = "network_va.connector"
)

// VantageInternet is the default vantage: the public internet.
const VantageInternet = ""

// Bounds of stored text (the columns' sizes).
const (
	MaxCodeLen  = 64
	MaxErrorLen = 500
)

var capabilityRe = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// ValidCapability reports whether c is a capability key ("<verb>.<object>").
func ValidCapability(c string) bool {
	return len(c) <= MaxCodeLen && capabilityRe.MatchString(c)
}

// Pair names one ledger row.
type Pair struct {
	TenantID   shared.ID
	AssetID    shared.ID
	Capability string
	Vantage    string
}

// Validate checks the pair's keys.
func (p Pair) Validate() error {
	if p.TenantID.IsZero() || p.AssetID.IsZero() {
		return fmt.Errorf("%w: coverage pair needs a tenant and an asset", shared.ErrValidation)
	}
	if !ValidCapability(p.Capability) {
		return fmt.Errorf("%w: coverage capability %q is not <verb>.<object>", shared.ErrValidation, p.Capability)
	}
	if len(p.Vantage) > MaxCodeLen {
		return fmt.Errorf("%w: coverage vantage is too long", shared.ErrValidation)
	}
	return nil
}

// Row is one ledger row as read.
type Row struct {
	Pair
	State         State
	Reason        string
	Priority      int
	NextDueAt     *time.Time
	QueuedAt      *time.Time
	LastAttemptAt *time.Time
	LastSuccessAt *time.Time
	LastOutcome   string
	LastError     string
	LastTool      string
	LastRunID     *shared.ID
	FailStreak    int
	// UnreachedFromName is the name of the organization's scan zone or
	// sensor recorded as the observer of a target-side outcome; filled by
	// the asset read only, "" for a platform sensor or none.
	UnreachedFromName string
	ChangeToken       int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Clip bounds a stored code or message to n bytes.
func Clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
