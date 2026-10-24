package contentsource

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SnapshotState is a snapshot's place in the source's history. Which
// snapshots are current and previous is held by the source.
type SnapshotState string

// Snapshot states.
const (
	StateCandidate  SnapshotState = "candidate"
	StatePromoted   SnapshotState = "promoted"
	StateSuperseded SnapshotState = "superseded"
	StateRejected   SnapshotState = "rejected"
)

// FileEntry is one file of a snapshot.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Rule is one rule (or template, or wordlist file) of a snapshot, with the
// hash of its own definition, so a diff can tell a changed rule from an
// unchanged one.
type Rule struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Path   string `json:"path"`
}

// MaxDiffIDs bounds each list of a Diff.
const MaxDiffIDs = 2000

// Diff is what a snapshot changes against its base (the source's current
// snapshot when it was taken).
type Diff struct {
	BaseSnapshotID string           `json:"base_snapshot_id,omitempty"`
	BaseCommit     string           `json:"base_commit,omitempty"`
	Added          []string         `json:"added"`
	Removed        []string         `json:"removed"`
	Changed        []string         `json:"changed"`
	AddedCount     int              `json:"added_count"`
	RemovedCount   int              `json:"removed_count"`
	ChangedCount   int              `json:"changed_count"`
	TierFrom       contentpack.Tier `json:"tier_from,omitempty"`
	TierTo         contentpack.Tier `json:"tier_to"`
	LicenseFrom    string           `json:"license_from,omitempty"`
	LicenseTo      string           `json:"license_to,omitempty"`
	Truncated      bool             `json:"truncated,omitempty"`
}

// Check codes that stop a candidate from being promoted automatically.
const (
	CheckPolicyReview     = "POLICY_REVIEW"
	CheckTierRaised       = "TIER_RAISED"
	CheckLicenseChanged   = "LICENSE_CHANGED"
	CheckLicenseNoService = "LICENSE_NO_SERVICE"
	CheckMassRemoval      = "MASS_REMOVAL"
	CheckDuplicateRuleIDs = "DUPLICATE_RULE_IDS"
)

// Checks is the promotion verdict on a candidate.
type Checks struct {
	AutoPromote bool     `json:"auto_promote"`
	Blocked     []string `json:"blocked,omitempty"`
}

// Snapshot is an immutable, signed state of a source.
type Snapshot struct {
	ID               shared.ID
	SourceID         shared.ID
	Scope            Scope
	TenantID         *shared.ID
	UpstreamRevision string
	Ref              string
	Digest           string
	ContentPackID    *shared.ID // tenant snapshots
	PlatformPackID   *shared.ID // platform snapshots
	SizeBytes        int64
	FileCount        int
	FileIndex        []FileEntry
	Rules            []Rule
	RuleCount        int
	Tier             contentpack.Tier
	Lint             contentpack.LintReport
	LicenseSPDX      string
	// ServiceUse: the license allows running the rules as a service.
	ServiceUse bool
	// Redistribution: the license allows passing the rules on (nil unknown).
	Redistribution *bool
	Signature      []byte
	Diff           Diff
	Checks         Checks
	ReviewRequired bool
	State          SnapshotState
	SyncedBy       *shared.ID
	PromotedBy     *shared.ID
	PromotedAt     *time.Time
	RejectedBy     *shared.ID
	RejectedAt     *time.Time
	RejectReason   string
	CreatedAt      time.Time
}

// ComputeDiff compares a candidate's rules, tier and license with base (nil
// for the first snapshot of a source).
func ComputeDiff(base *Snapshot, rules []Rule, tier contentpack.Tier, license string) Diff {
	d := Diff{TierTo: tier, LicenseTo: license, Added: []string{}, Removed: []string{}, Changed: []string{}}
	old := map[string]string{}
	if base != nil {
		d.BaseSnapshotID, d.BaseCommit = base.ID.String(), base.UpstreamRevision
		d.TierFrom, d.LicenseFrom = base.Tier, base.LicenseSPDX
		for _, r := range base.Rules {
			old[r.ID] = r.SHA256
		}
	}
	add := func(list *[]string, n *int, id string) {
		*n++
		if len(*list) >= MaxDiffIDs {
			d.Truncated = true
			return
		}
		*list = append(*list, id)
	}
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		seen[r.ID] = true
		h, ok := old[r.ID]
		switch {
		case !ok:
			add(&d.Added, &d.AddedCount, r.ID)
		case h != r.SHA256:
			add(&d.Changed, &d.ChangedCount, r.ID)
		}
	}
	if base != nil {
		for _, r := range base.Rules {
			if !seen[r.ID] {
				seen[r.ID] = true
				add(&d.Removed, &d.RemovedCount, r.ID)
			}
		}
	}
	return d
}

// massRemoval is true when a candidate removes more than a fifth of the
// base's rules, and more than five of them.
func massRemoval(base *Snapshot, d Diff) bool {
	if base == nil || base.RuleCount == 0 {
		return false
	}
	return d.RemovedCount > 5 && d.RemovedCount*5 > base.RuleCount
}

// NoServiceLicenses are licenses that forbid offering the rules as a
// service; such a candidate is never promoted automatically.
var NoServiceLicenses = map[string]bool{
	"LicenseRef-Semgrep-Rules":  true,
	"LicenseRef-Commons-Clause": true,
}

// EvaluatePromotion decides whether a candidate may be promoted without a
// person, and whether it needs a second member (four-eyes). A candidate
// that raises the tier always needs review, whatever the policy; the first
// snapshot of a source is compared with T0 and no license.
func EvaluatePromotion(policy PromotionPolicy, base *Snapshot, cand *Snapshot, duplicateIDs bool) (Checks, bool) {
	var blocked []string
	review := policy == PolicyReview
	if review {
		blocked = append(blocked, CheckPolicyReview)
	}
	baseTier := contentpack.TierT0
	baseLicense := ""
	if base != nil {
		baseTier, baseLicense = base.Tier, base.LicenseSPDX
	}
	if cand.Tier.Rank() > baseTier.Rank() {
		blocked = append(blocked, CheckTierRaised)
		review = true
	}
	if base != nil && cand.LicenseSPDX != baseLicense {
		blocked = append(blocked, CheckLicenseChanged)
	}
	if NoServiceLicenses[cand.LicenseSPDX] {
		blocked = append(blocked, CheckLicenseNoService)
	}
	if massRemoval(base, cand.Diff) {
		blocked = append(blocked, CheckMassRemoval)
	}
	if duplicateIDs {
		blocked = append(blocked, CheckDuplicateRuleIDs)
	}
	return Checks{AutoPromote: len(blocked) == 0, Blocked: blocked}, review
}
