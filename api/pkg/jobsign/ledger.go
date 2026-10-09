package jobsign

// The job signer's scope ledger: the wire format between the API and the
// signer, and the one rule both sides use to tell a widening from a
// narrowing. Design: docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
// §5.6 points 4 and 5; format and ceremony:
// docs/architecture/job-signing.md ("Scope ledger").

import (
	"fmt"
	"time"
)

// Paths of the ledger API on the signer's socket.
const (
	LedgerPath      = "/v1/ledger"
	LedgerApplyPath = "/v1/ledger/apply"
	LedgerSyncPath  = "/v1/ledger/sync"
)

// SnapshotKind is the kind of a ledger snapshot file (server
// -signer-ledger-export, openctem-signer ledger import).
const SnapshotKind = "openctem.ledger-snapshot/v1"

// Ledger limits the signer enforces.
const (
	// MaxLedgerBodyBytes caps an apply or sync request.
	MaxLedgerBodyBytes = 16 << 20
	// MaxLedgerOps caps the operations of one change.
	MaxLedgerOps = 1000
	// MaxLedgerEntries and MaxLedgerExclusions cap one organization's
	// ledger (and one snapshot of it).
	MaxLedgerEntries    = 10000
	MaxLedgerExclusions = 10000
	// MaxLedgerApprovals caps the approvals of one change.
	MaxLedgerApprovals = 16
	// MaxLedgerPatternBytes caps a pattern (the API's own cap).
	MaxLedgerPatternBytes = 500
	// MaxPolicyApprovals is the highest approval count a policy can ask.
	MaxPolicyApprovals = 2
	// MaxPlatformPolicyBytes caps the platform policy label.
	MaxPlatformPolicyBytes = 64
)

// Tiers of an entry (RFC-036 / RFC-054): 0 passive, 1 safe active, 2
// intrusive.
const (
	TierPassive   = 0
	TierActive    = 1
	TierIntrusive = 2
)

// LedgerEntry is a scope entry in effect: what the organization approved
// for active probes.
type LedgerEntry struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	MaxTier int    `json:"max_tier"`
	// ExpiresAt is when the entry stops authorizing (nil: permanent). The
	// signer applies it with its own clock.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// LedgerExclusion is a scope exclusion in effect. Only target exclusions
// (domain, subdomain, ip_address, ip_range, cidr, url, repository) are in
// the ledger.
type LedgerExclusion struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	Pattern   string     `json:"pattern"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// LedgerApproval is one person's approval of a widening, as the API
// recorded it (P2; WebAuthn assertions over the change in P3).
type LedgerApproval struct {
	UserID     string    `json:"user_id"`
	ApprovedAt time.Time `json:"approved_at"`
	// SelfApproved: the requester approved their own change under the
	// policy's sole-owner rule (RFC-054 §12 A2). It counts only for the
	// requester and only once.
	SelfApproved bool `json:"self_approved,omitempty"`
}

// Ledger operations.
const (
	OpPutEntry        = "put_entry"
	OpRemoveEntry     = "remove_entry"
	OpPutExclusion    = "put_exclusion"
	OpRemoveExclusion = "remove_exclusion"
)

// LedgerOp is one operation of a change: put_entry and put_exclusion carry
// the item, the remove operations its id.
type LedgerOp struct {
	Op        string           `json:"op"`
	Entry     *LedgerEntry     `json:"entry,omitempty"`
	Exclusion *LedgerExclusion `json:"exclusion,omitempty"`
	ID        string           `json:"id,omitempty"`
}

// LedgerChange is POST /v1/ledger/apply: one change to one organization's
// ledger. The signer decides whether it widens (any operation widens) and,
// if so, whether the approvals meet the policy.
type LedgerChange struct {
	TenantID string `json:"tenant_id"`
	// ChangeID names the change in both audit trails (a UUID).
	ChangeID string `json:"change_id"`
	// Requester is who asked for the change ("" for a system path).
	Requester string           `json:"requester"`
	Approvals []LedgerApproval `json:"approvals"`
	// RequiredApprovals is the approval count the organization's policy
	// asks of this change (scope.Service; 0..2).
	RequiredApprovals int `json:"policy_required_approvals"`
	// PlatformPolicy labels the platform approval policy in force, for the
	// record.
	PlatformPolicy string     `json:"platform_policy,omitempty"`
	Ops            []LedgerOp `json:"ops"`
}

// Kinds of a ledger change.
const (
	ChangeWiden  = "widen"
	ChangeNarrow = "narrow"
	ChangeNoop   = "noop"
)

// Ledger modes.
const (
	LedgerEnforce = "enforce"
	LedgerAudit   = "audit"
	LedgerOff     = "off"
)

// LedgerApplyResult answers an apply.
type LedgerApplyResult struct {
	Kind string `json:"kind"`
	Mode string `json:"mode"`
}

// LedgerSnapshot is one organization's scope in effect as the API's
// database holds it: the body of POST /v1/ledger/sync and one organization
// of a snapshot file.
type LedgerSnapshot struct {
	TenantID   string            `json:"tenant_id"`
	Entries    []LedgerEntry     `json:"entries"`
	Exclusions []LedgerExclusion `json:"exclusions"`
}

// LedgerSyncResult answers a sync: what it narrowed, and how many items the
// snapshot holds wider than the ledger (left as they are: a sync never
// widens).
type LedgerSyncResult struct {
	Mode     string `json:"mode"`
	Narrowed int    `json:"narrowed"`
	Diverged int    `json:"diverged"`
}

// LedgerStatus is GET /v1/ledger.
type LedgerStatus struct {
	Mode    string   `json:"mode"`
	Tenants []string `json:"tenants"`
}

// LedgerExport is a snapshot file.
type LedgerExport struct {
	Kind      string           `json:"kind"`
	CreatedAt time.Time        `json:"created_at"`
	Tenants   []LedgerSnapshot `json:"tenants"`
}

// Expired reports whether an expiry has passed at now.
func Expired(at *time.Time, now time.Time) bool { return at != nil && !at.After(now) }

// laterEnd reports whether next ends later than prev (nil: never).
func laterEnd(prev, next *time.Time) bool {
	switch {
	case prev == nil:
		return false
	case next == nil:
		return true
	}
	return next.After(*prev)
}

// EntryWidens reports whether putting next where old is (nil: no entry, or
// none in effect) widens what the organization authorizes: a new entry, a
// different type or pattern, a higher tier, or a later or removed expiry.
func EntryWidens(old *LedgerEntry, next LedgerEntry, now time.Time) bool {
	if old == nil || Expired(old.ExpiresAt, now) {
		return true
	}
	return old.Type != next.Type || old.Pattern != next.Pattern ||
		next.MaxTier > old.MaxTier || laterEnd(old.ExpiresAt, next.ExpiresAt)
}

// ExclusionPutWidens reports whether putting next where old is (nil: no
// exclusion) widens: a different type or pattern (the old one goes), or an
// earlier or newly set expiry. A new exclusion narrows.
func ExclusionPutWidens(old *LedgerExclusion, next LedgerExclusion, now time.Time) bool {
	if old == nil || Expired(old.ExpiresAt, now) {
		return false
	}
	return old.Type != next.Type || old.Pattern != next.Pattern || laterEnd(next.ExpiresAt, old.ExpiresAt)
}

// ExclusionRemoveWidens reports whether removing old widens: it does while
// old is still in effect.
func ExclusionRemoveWidens(old *LedgerExclusion, now time.Time) bool {
	return old != nil && !Expired(old.ExpiresAt, now)
}

// Ledger refusal reasons (sign time and ledger changes).
const (
	ReasonOutOfLedger       = "out_of_ledger"
	ReasonTierExceedsLedger = "tier_exceeds_ledger"
	ReasonTargetExcluded    = "target_excluded"
	ReasonLedgerMalformed   = "ledger_malformed"
	ReasonLedgerTooLarge    = "ledger_too_large"
	ReasonLedgerNotApproved = "ledger_not_approved"
)

// RefusalError is a refusal (4xx) the signer answered.
type RefusalError struct {
	Status int
	Reason string
	Detail string
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("job signer refused (%d %s): %s", e.Status, e.Reason, e.Detail)
}

// Permanent reports whether the signer will refuse the same request again
// while its ledger stands (403): a job or change it does not authorize, as
// opposed to a malformed or rate-limited request.
func (e *RefusalError) Permanent() bool { return e.Status == 403 }
