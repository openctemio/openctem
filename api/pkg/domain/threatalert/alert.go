// Package threatalert is the emerging-threat alert: one per organization
// and vulnerability, the unit of attention above findings. It holds the
// affected assets in two tiers (confirmed, possibly affected), a transparent
// Emerging Threat Score and the level that decides delivery (immediate,
// daily digest, listed only).
//
// Design: docs/rfcs/RFC-117-emerging-threat-alerts.md.
package threatalert

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Level decides delivery.
type Level string

// Levels, most urgent first.
const (
	LevelImmediate Level = "immediate"
	LevelDigest    Level = "digest"
	LevelListed    Level = "listed"
)

// Rank orders levels (higher is more urgent); notified "none" is 0.
func (l Level) Rank() int {
	switch l {
	case LevelImmediate:
		return 3
	case LevelDigest:
		return 2
	case LevelListed:
		return 1
	}
	return 0
}

// IsValid reports whether l is a level.
func (l Level) IsValid() bool { return l.Rank() > 0 }

// Notified levels besides LevelDigest and LevelImmediate.
const NotifiedNone = "none"

// Tier is how sure the platform is that the organization is affected.
type Tier string

// Tiers.
const (
	TierConfirmed Tier = "confirmed"
	TierPossible  Tier = "possible"
)

// IsValid reports whether t is a tier.
func (t Tier) IsValid() bool { return t == TierConfirmed || t == TierPossible }

// MatchKind is how one asset is affected.
type MatchKind string

// Match kinds.
const (
	// MatchConfirmed: an open finding for the vulnerability.
	MatchConfirmed MatchKind = "confirmed"
	// MatchLikely: a version match below the confirmed confidence.
	MatchLikely MatchKind = "likely"
	// MatchPossible: the product is known on the asset, its version is not.
	MatchPossible MatchKind = "possible"
)

// ConfirmedConfidence is the match confidence from which a version match
// counts as confirmed.
const ConfirmedConfidence = 80

// State is the triage state.
type State string

// States.
const (
	StateNew          State = "new"
	StateAcknowledged State = "acknowledged"
	StateRemediating  State = "remediating"
	StateNotAffected  State = "not_affected"
	StateResolved     State = "resolved"
)

// IsOpen reports whether the alert still needs attention.
func (s State) IsOpen() bool {
	return s == StateNew || s == StateAcknowledged || s == StateRemediating
}

// IsValid reports whether s is a state.
func (s State) IsValid() bool { return s.IsOpen() || s == StateNotAffected || s == StateResolved }

// Not-affected reasons.
const (
	ReasonVersionNotAffected  = "version_not_affected"
	ReasonFeatureNotUsed      = "feature_not_used"
	ReasonCompensatingControl = "compensating_control"
	ReasonWrongProduct        = "wrong_product"
	ReasonAssetDecommissioned = "asset_decommissioned"
	// ReasonRejectedUpstream resolves alerts of a rejected CVE.
	ReasonRejectedUpstream = "rejected_upstream"
	// ReasonFixed resolves an alert whose affected assets are all gone.
	ReasonFixed = "fixed"
)

// NotAffectedReasons are the reasons a person may give.
func NotAffectedReasons() []string {
	return []string{ReasonVersionNotAffected, ReasonFeatureNotUsed, ReasonCompensatingControl, ReasonWrongProduct, ReasonAssetDecommissioned}
}

// SuppressFor is how long "not affected" suppresses an alert.
const SuppressFor = 180 * 24 * time.Hour

// MaxNoteLength bounds the free-text note of a triage decision.
const MaxNoteLength = 500

// Errors.
var (
	ErrNotFound = fmt.Errorf("%w: emerging-threat alert not found", shared.ErrNotFound)
	// ErrOutOfScope: the alert has assets outside the caller's data scope,
	// so the caller may not suppress it.
	ErrOutOfScope = fmt.Errorf("%w: the alert has assets outside your data scope", shared.ErrConflict)
)

// ValidateTransition checks a person's triage decision.
func ValidateTransition(to State, reason, note string) error {
	switch to {
	case StateNew, StateAcknowledged, StateRemediating:
	case StateNotAffected:
		ok := false
		for _, r := range NotAffectedReasons() {
			if reason == r {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%w: reason must be one of %s", shared.ErrValidation, strings.Join(NotAffectedReasons(), ", "))
		}
	default:
		return fmt.Errorf("%w: state must be new, acknowledged, remediating or not_affected", shared.ErrValidation)
	}
	if len(note) > MaxNoteLength {
		return fmt.Errorf("%w: note must be at most %d characters", shared.ErrValidation, MaxNoteLength)
	}
	return nil
}

// ReopenedBy reports whether a suppressed (not affected) alert is reopened
// by a new fact: a stronger match (possibly affected became confirmed), or
// a KEV addition when the reason was not about the version or the product.
func ReopenedBy(reason string, wasTier, nowTier Tier, kevAdded bool) bool {
	if wasTier == TierPossible && nowTier == TierConfirmed {
		return true
	}
	return kevAdded && reason != ReasonVersionNotAffected && reason != ReasonWrongProduct
}

// Vuln is what the platform knows of a vulnerability (public facts).
type Vuln struct {
	ID            string
	Severity      string
	CVSSScore     *float64
	CVSSVector    string
	Description   string
	Published     *time.Time
	Rejected      bool
	InKEV         bool
	KEVRansomware bool
	KEVDateAdded  *time.Time
	EPSS          *float64
	// LastEventKind and LastEventAt are the newest material event; SourceAt
	// is when the source says the triggering fact happened.
	LastEventKind string
	LastEventAt   *time.Time
	SourceAt      *time.Time
}

// Asset is one affected asset as the planner saw it.
type Asset struct {
	AssetID        shared.ID
	Name           string
	Type           string
	Kind           MatchKind
	Confidence     int
	InternetFacing bool
	Criticality    string
	Product        string
	Version        string
	FindingID      *shared.ID
}

// Breakdown is the Emerging Threat Score and its parts.
type Breakdown struct {
	Exploitation int     `json:"exploitation"`
	Severity     int     `json:"severity"`
	Exposure     int     `json:"exposure"`
	Freshness    int     `json:"freshness"`
	Confidence   float64 `json:"confidence"`
	Total        int     `json:"total"`
}

// Freshness window of the triggering event.
const FreshFor = 72 * time.Hour

func exploitationPoints(v Vuln) int {
	p := 0
	switch {
	case v.InKEV:
		p = 40
	case v.EPSS != nil && *v.EPSS >= 0.5:
		p = 20
	case v.EPSS != nil && *v.EPSS >= 0.1:
		p = 10
	}
	if v.InKEV && v.KEVRansomware {
		p += 5
	}
	return p
}

func severityPoints(v Vuln) int {
	p := 0
	switch strings.ToLower(v.Severity) {
	case "critical":
		p = 20
	case "high":
		p = 12
	case "medium":
		p = 5
	}
	vec := strings.ToUpper(v.CVSSVector)
	if strings.Contains(vec, "AV:N") && strings.Contains(vec, "PR:N") && strings.Contains(vec, "UI:N") {
		p += 5
	}
	return p
}

func exposurePoints(assets []Asset) int {
	best := 0
	for _, a := range assets {
		p := 0
		crown := strings.EqualFold(a.Criticality, "critical")
		switch {
		case a.InternetFacing && crown:
			p = 30
		case a.InternetFacing:
			p = 20
		case crown:
			p = 15
		}
		best = max(best, p)
	}
	return best
}

// Score computes the Emerging Threat Score for the best tier: confirmed
// assets (confidence 1.0, or 0.8 when every one is only likely), else
// possibly affected ones (0.5).
func Score(v Vuln, assets []Asset, now time.Time) (Breakdown, Tier) {
	confirmed := make([]Asset, 0, len(assets))
	var possible []Asset
	anyConfirmed := false
	for _, a := range assets {
		if a.Kind == MatchPossible {
			possible = append(possible, a)
			continue
		}
		confirmed = append(confirmed, a)
		if a.Kind == MatchConfirmed {
			anyConfirmed = true
		}
	}
	base := Breakdown{Exploitation: exploitationPoints(v), Severity: severityPoints(v)}
	if v.LastEventAt != nil && now.Sub(*v.LastEventAt) < FreshFor {
		base.Freshness = 10
	}
	score := func(group []Asset, conf float64) Breakdown {
		b := base
		b.Exposure = exposurePoints(group)
		b.Confidence = conf
		raw := float64(b.Exploitation+b.Severity+b.Exposure+b.Freshness) * conf
		b.Total = min(100, int(math.Round(raw)))
		return b
	}
	var best Breakdown
	tier := TierPossible
	if len(possible) > 0 {
		best = score(possible, 0.5)
	}
	if len(confirmed) > 0 {
		conf := 0.8
		if anyConfirmed {
			conf = 1.0
		}
		if b := score(confirmed, conf); b.Total >= best.Total || len(possible) == 0 {
			best, tier = b, TierConfirmed
		}
	}
	return best, tier
}

// LevelFor routes an alert. Immediate needs the threshold and exploitation
// evidence (never severity alone); possibly affected assets page only when
// the CVE is in KEV on an internet-facing asset, unless the organization
// opts in. minSeverityPasses is the organization's vulnerability matching
// minimum severity applied to the CVE.
func LevelFor(b Breakdown, tier Tier, v Vuln, assets []Asset, s tenant.EmergingThreatSettings, minSeverityPasses bool) Level {
	s = s.Effective()
	if b.Total >= s.ImmediateThreshold && b.Exploitation >= 20 {
		if tier == TierConfirmed || s.IncludePossibleInImmediate || (v.InKEV && anyInternetFacing(assets, MatchPossible)) {
			return LevelImmediate
		}
	}
	if b.Total >= s.DigestThreshold || minSeverityPasses {
		return LevelDigest
	}
	return LevelListed
}

func anyInternetFacing(assets []Asset, kind MatchKind) bool {
	for _, a := range assets {
		if a.Kind == kind && a.InternetFacing {
			return true
		}
	}
	return false
}

// Recommended actions.
const (
	ActionPatchNow       = "patch_now"
	ActionConfirm        = "confirm"
	ActionPatchWithinSLA = "patch_within_sla"
)

// RecommendedAction is the one-line advice for an alert.
func RecommendedAction(tier Tier, b Breakdown) string {
	switch {
	case tier == TierPossible:
		return ActionConfirm
	case b.Exploitation >= 20:
		return ActionPatchNow
	}
	return ActionPatchWithinSLA
}

// Alert is one organization's alert for one vulnerability.
type Alert struct {
	ID              shared.ID
	TenantID        shared.ID
	VulnID          string
	Title           string
	Severity        string
	Level           Level
	Tier            Tier
	State           State
	StateReason     string
	StateNote       string
	StateChangedBy  *shared.ID
	StateChangedAt  *time.Time
	SuppressedUntil *time.Time
	ETS             int
	Breakdown       Breakdown
	InKEV           bool
	KEVRansomware   bool
	EPSS            *float64
	Confirmed       int
	Possible        int
	InternetFacing  int
	LastEventKind   string
	SourceAt        *time.Time
	EventAt         *time.Time
	NotifiedLevel   string
	NotifiedTier    string
	NotifiedAt      *time.Time
	DigestPending   bool
	Held            bool
	Baseline        bool
	PlannedAt       time.Time
	AcknowledgedAt  *time.Time
	ResolvedAt      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Counts sets the asset counts from the affected assets.
func (a *Alert) Counts(assets []Asset) {
	a.Confirmed, a.Possible, a.InternetFacing = 0, 0, 0
	for _, x := range assets {
		if x.Kind == MatchPossible {
			a.Possible++
		} else {
			a.Confirmed++
		}
		if x.InternetFacing {
			a.InternetFacing++
		}
	}
}

// ErrInvalid wraps a domain validation failure.
var ErrInvalid = errors.New("invalid emerging-threat alert")

// maxTitle bounds an alert title.
const maxTitle = 200

// PlainText makes untrusted text (catalog product names, CVE text) safe for
// a channel message: control characters and channel markup (<, >, &, @, `,
// *, _, ~, |) become spaces, runs of spaces collapse, and the result is cut
// at limit runes.
func PlainText(s string, limit int) string {
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if n >= limit {
			break
		}
		if unicode.IsControl(r) || strings.ContainsRune("<>&@`*_~|[]", r) || unicode.IsSpace(r) {
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
				space = true
				n++
			}
			continue
		}
		b.WriteRune(r)
		space = false
		n++
	}
	return strings.TrimSpace(b.String())
}

// Title is the alert title: the vulnerability id and the affected product.
func Title(vulnID, product string) string {
	p := PlainText(product, 120)
	if p == "" {
		return PlainText(vulnID, maxTitle)
	}
	return PlainText(vulnID, 64) + " · " + p
}
