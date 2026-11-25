// Package threatalert is the emerging-threat alert: one per organization
// and vulnerability, the unit of attention above findings. It holds the
// affected assets in two tiers (confirmed, possibly affected), counted by
// host (hosts.go), a transparent
// Emerging Threat Score and the level that decides delivery (immediate,
// daily digest, listed only).
//
// Design: docs/rfcs/RFC-117-emerging-threat-alerts.md.
package threatalert

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/openctem/server/pkg/domain/advisory"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
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
	// ReasonGroupedIntoCard resolves a vulnerability's alert once an
	// advisory card groups it: the card's alert carries it on (the card id
	// is in its own column; the person's note and the actor stay, nothing
	// is deleted).
	ReasonGroupedIntoCard = "grouped_into_card"
	// ReasonCardWithdrawn resolves a card's alerts when the card is
	// withdrawn.
	ReasonCardWithdrawn = "card_withdrawn"
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
	// ErrStale: the alert changed (a triage decision) after the planner
	// read it; the planner plans it again from the stored alert.
	ErrStale = fmt.Errorf("%w: the emerging-threat alert changed since it was read", shared.ErrConflict)
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
	ID string
	// Title is the advisory card's title (empty for a CVE).
	Title         string
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
	// Exploitation is the strongest status a reviewed advisory card states
	// (none when no card names the vulnerability); ExploitationSources are
	// the public sources the card cites for it.
	Exploitation        advisory.Exploitation
	ExploitationSources []string
	// CardID is set when the alert key is an advisory card: the facts above
	// then cover every vulnerability the card groups.
	CardID string
	// Grouped lists the vulnerability ids the card groups.
	Grouped []string
	// CardReported is set for a card in the fast lane (reported, not yet
	// reviewed): it alerts but groups nothing, and its exploitation status
	// is not counted.
	CardReported bool
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
	Exploitation int `json:"exploitation"`
	// ExploitationBasis names the evidence the exploitation points come
	// from (an ExploitBasis value; empty when none).
	ExploitationBasis string  `json:"exploitation_basis,omitempty"`
	Severity          int     `json:"severity"`
	Exposure          int     `json:"exposure"`
	Freshness         int     `json:"freshness"`
	Confidence        float64 `json:"confidence"`
	Total             int     `json:"total"`
}

// Freshness window of the triggering event.
const FreshFor = 72 * time.Hour

// Exploitation evidence named in the score breakdown.
const (
	BasisKEV             = "kev"
	BasisVendorConfirmed = "vendor_confirmed_exploited"
	BasisInTheWild       = "exploited_itw"
	BasisWeaponised      = "weaponised"
	BasisPoCPublic       = "poc_public"
	BasisEPSSHigh        = "epss_high"
	BasisEPSS            = "epss"
)

// exploitationPoints scores the strongest exploitation evidence: KEV or a
// reviewed card saying exploitation was confirmed by the vendor or seen in
// the wild 40, a weaponised exploit 30, a public proof of concept or EPSS at
// least 0.5 20, EPSS at least 0.1 10; KEV ransomware use adds 5. A day-0
// vulnerability has no KEV entry and no EPSS score, so the card is what
// lets it count.
func exploitationPoints(v Vuln) (int, string) {
	type cand struct {
		p     int
		basis string
	}
	best := cand{}
	try := func(ok bool, p int, basis string) {
		if ok && p > best.p {
			best = cand{p, basis}
		}
	}
	try(v.InKEV, 40, BasisKEV)
	try(v.Exploitation == advisory.ExploitVendorConfirmed, 40, BasisVendorConfirmed)
	try(v.Exploitation == advisory.ExploitInTheWild, 40, BasisInTheWild)
	try(v.Exploitation == advisory.ExploitWeaponised, 30, BasisWeaponised)
	try(v.Exploitation == advisory.ExploitPoCPublic, 20, BasisPoCPublic)
	try(v.EPSS != nil && *v.EPSS >= 0.5, 20, BasisEPSSHigh)
	try(v.EPSS != nil && *v.EPSS >= 0.1, 10, BasisEPSS)
	if v.InKEV && v.KEVRansomware {
		best.p += 5
	}
	return best.p, best.basis
}

// PublicExploit reports whether working exploitation of the vulnerability
// is public: KEV, or a reviewed card stating a public proof of concept or
// stronger. EPSS alone is a prediction, not evidence.
func (v Vuln) PublicExploit() bool { return v.InKEV || v.Exploitation.PublicExploit() }

func severityPoints(v Vuln) int {
	p := 0
	switch strings.ToLower(v.Severity) {
	case levelCritical:
		p = 20
	case levelHigh:
		p = 12
	case levelMedium:
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
		crown := strings.EqualFold(a.Criticality, levelCritical)
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
	ep, basis := exploitationPoints(v)
	base := Breakdown{Exploitation: ep, ExploitationBasis: basis, Severity: severityPoints(v)}
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
//
// One narrow exception does not need the threshold: a critical
// vulnerability with a public exploit (KEV or a reviewed card) on a possibly
// affected asset that is both internet-facing and of critical business
// criticality. The version is unknown, so the message is a "check needed"
// (RecommendedAction confirm), and it is sent once per alert like any
// immediate one.
func LevelFor(b Breakdown, tier Tier, v Vuln, assets []Asset, s tenant.EmergingThreatSettings, minSeverityPasses bool) Level {
	s = s.Effective()
	if b.Total >= s.ImmediateThreshold && b.Exploitation >= 20 {
		if tier == TierConfirmed || s.IncludePossibleInImmediate || (v.InKEV && anyInternetFacing(assets, MatchPossible)) {
			return LevelImmediate
		}
	}
	if CheckNeeded(tier, v, assets) {
		return LevelImmediate
	}
	if b.Total >= s.DigestThreshold || minSeverityPasses {
		return LevelDigest
	}
	return LevelListed
}

// CheckNeeded reports the "check needed" case of LevelFor: possibly
// affected only, a critical vulnerability with a public exploit, and an
// internet-facing crown-jewel asset among the possibly affected ones.
func CheckNeeded(tier Tier, v Vuln, assets []Asset) bool {
	if v.CardReported || tier != TierPossible || !strings.EqualFold(v.Severity, levelCritical) || !v.PublicExploit() {
		return false
	}
	for _, a := range assets {
		if a.Kind == MatchPossible && a.InternetFacing && strings.EqualFold(a.Criticality, levelCritical) {
			return true
		}
	}
	return false
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
	// Confirmed, Likely, Possible and InternetFacing count hosts
	// (HostCounts): a host that serves several ports is one. The stored
	// values cover the whole organization; a viewer reads them over the
	// assets in their scope.
	Confirmed      int
	Likely         int
	Possible       int
	InternetFacing int
	// Critical counts the affected hosts of criticality "critical" (the
	// crown jewels); Product is the product the best match names and
	// ProductCount how many distinct products match. They are read over the
	// viewer's in-scope assets only.
	Critical       int
	Product        string
	ProductCount   int
	LastEventKind  string
	SourceAt       *time.Time
	EventAt        *time.Time
	NotifiedLevel  string
	NotifiedTier   string
	NotifiedAt     *time.Time
	DigestPending  bool
	Held           bool
	Baseline       bool
	PlannedAt      time.Time
	AcknowledgedAt *time.Time
	ResolvedAt     *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Counts sets the host counts from the affected assets.
func (a *Alert) Counts(assets []Asset) {
	c := CountHosts(assets)
	a.Confirmed, a.Likely, a.Possible, a.InternetFacing = c.Confirmed, c.Likely, c.Possible, c.InternetFacing
}

// HostCounts is the alert's counts as one value.
func (a *Alert) HostCounts() HostCounts {
	return HostCounts{Confirmed: a.Confirmed, Likely: a.Likely, Possible: a.Possible,
		InternetFacing: a.InternetFacing, Critical: a.Critical}
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

// CardTitle is the title of an alert keyed by an advisory card: the card's
// own title, as plain text. A reported card (fast lane) says so first.
func CardTitle(title string, reported bool) string {
	if reported {
		title = ReportedPrefix + title
	}
	return PlainText(title, maxTitle)
}

// ReportedPrefix marks the title of an alert from a card no person has
// reviewed yet.
const ReportedPrefix = "Reported, not yet reviewed: "

// severities, weakest first.
var severities = []string{"none", "low", levelMedium, levelHigh, levelCritical}

// StrongestSeverity is the strongest of the given severity levels (empty
// when none is known). A card's alert never rates lower than a
// vulnerability it groups.
func StrongestSeverity(levels ...string) string {
	best, rank := "", -1
	for _, l := range levels {
		l = strings.ToLower(l)
		if r := slices.Index(severities, l); r > rank {
			best, rank = l, r
		}
	}
	return best
}

// CardSeverity is the severity of a card's alert: the strongest of the
// card's own level and the severity of the CVE records it groups. A
// reported card (no person has reviewed it) never raises it by its own
// claim: when any record has a severity, only the records count, and the
// card's level is used only on day 0, before any record exists.
func CardSeverity(reported bool, own string, records ...string) string {
	if reported {
		if s := StrongestSeverity(records...); s != "" {
			return s
		}
		return StrongestSeverity(own)
	}
	return StrongestSeverity(append(append([]string{}, records...), own)...)
}

// StrongerTriage is the stronger of two open triage states (remediating
// over acknowledged over new); anything else counts as new.
func StrongerTriage(a, b State) State {
	rank := func(s State) int {
		switch s {
		case StateRemediating:
			return 2
		case StateAcknowledged:
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}
