package cirun

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Gate policy scopes, most specific last.
const (
	ScopeTenant       = "tenant"
	ScopeBusinessUnit = "business_unit"
	ScopeRepository   = "repository"
	// ScopeDefault is the built-in policy, used when the tenant set none.
	ScopeDefault = "default"
)

// Gate modes.
const (
	ModeEnforce = "enforce"
	// ModeWarn reports what would fail and passes.
	ModeWarn = "warn"
)

// SeverityNone disables the severity threshold.
const SeverityNone = "none"

// Reason codes of a verdict.
const (
	ReasonSecret      = "secret"
	ReasonKEV         = "kev"
	ReasonEPSS        = "epss"
	ReasonSeverity    = "severity"
	ReasonScanFailure = "scan_failure"
	// ReasonMissingCapability: the repository is expected to be scanned for
	// a capability (its coverage expectation) and the run reported no tool
	// with it, for example because the pipeline was edited to skip it.
	ReasonMissingCapability = "missing_capability"
	ReasonOverride          = "override"
	ReasonNoBaseline        = "no_baseline"
	// ReasonBaselineEstablished notes that this run recorded the
	// repository's first gate baseline: its open findings stopped blocking.
	ReasonBaselineEstablished = "baseline_established"
	// ReasonSecretPreExisting notes a secret already open on the baseline
	// branch: it blocks default-branch runs, not pull requests.
	ReasonSecretPreExisting = "secret_pre_existing"
	// ReasonCapabilityFailed: the job reported that a capability it ran
	// did not fully reach the platform (failed, partial, not uploaded or
	// missing), whatever its scan_failures count says.
	ReasonCapabilityFailed = "capability_failed"
	// ReasonTooManyFindings: the run reported more findings than the gate
	// records (MaxRunFindings), so it cannot be judged on all of them.
	ReasonTooManyFindings = "too_many_findings"
)

// CapabilityState is what the CI job reports about one capability at
// evaluation: its name, tool, state and a fixed reason word. Only
// CapabilityUploaded is a clean state; any other state fails the gate.
type CapabilityState struct {
	Name   string `json:"name"`
	Tool   string `json:"tool,omitempty"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// CapabilityUploaded is the state of a capability whose results all reached
// the platform. The CI runner also sends partial, failed, not_uploaded and
// missing; an unknown state counts as not clean (fail closed).
const CapabilityUploaded = "uploaded"

// MaxCapabilityStates bounds the capability states one evaluation reads.
const MaxCapabilityStates = 64

// FailedCapabilities returns the reported capabilities that are not clean,
// with their labels sanitized (they are job input, shown in the verdict and
// the merge request comment). Past MaxCapabilityStates the rest are ignored;
// an empty name is reported as "unknown".
func FailedCapabilities(states []CapabilityState) []CapabilityState {
	out := []CapabilityState{}
	for i, c := range states {
		if i >= MaxCapabilityStates {
			break
		}
		state := SanitizeLabel(strings.ToLower(c.State), 32)
		if state == CapabilityUploaded {
			continue
		}
		name := SanitizeLabel(c.Name, 64)
		if name == "" {
			name = "unknown"
		}
		if state == "" {
			state = "unknown"
		}
		out = append(out, CapabilityState{Name: name, Tool: SanitizeLabel(c.Tool, 64), State: state,
			Reason: SanitizeLabel(c.Reason, 64)})
	}
	return out
}

// Break-glass limits.
const (
	DefaultOverrideTTL = 24 * time.Hour
	MaxOverrideTTL     = 7 * 24 * time.Hour
	minOverrideReason  = 10
	maxOverrideReason  = 2000
)

// maxReasons caps the finding reasons listed in one verdict; the summary
// counts all of them.
const maxReasons = 50

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

// GatePolicy decides which findings of a run fail the pipeline. Secrets
// always fail and accepted risk is always honored: neither is a setting.
type GatePolicy struct {
	ID        shared.ID
	TenantID  shared.ID
	ScopeType string
	ScopeID   *shared.ID
	Enabled   bool
	Mode      string
	// FailOnSeverity is the lowest severity that fails (critical, high,
	// medium, low) or "none".
	FailOnSeverity string
	// NewFindingsOnly judges only findings the change introduces, compared
	// with the default branch.
	NewFindingsOnly bool
	FailOnKEV       bool
	// EPSSThreshold fails a finding whose EPSS score is at least this
	// (0..1); nil disables it.
	EPSSThreshold *float64
	// Modes sets block, comment or monitor per capability and rule.
	Modes PolicyModes
	// AllowRepoPolicy lets a repository's .openctem.yml tighten the gate and
	// request exceptions (default true; any policy saying no wins).
	AllowRepoPolicy bool
	// FixableOnly fails a dependency or image vulnerability on its severity
	// or EPSS score only when a fixed version exists; one with no fix is
	// listed, not blocking. KEV still fails, fixable or not.
	FixableOnly bool
	// BaselineOnFirstRun records the repository's gate baseline on its first
	// verified default-branch run (default on; off: an administrator records
	// it).
	BaselineOnFirstRun bool
	// BaselineGraceDays: baseline findings stop counting as pre-existing
	// this many days after the baseline was recorded (nil: no end). Their
	// due date is the end of the grace.
	BaselineGraceDays *int
	// BaselineSecretsBlock: a secret in the baseline still blocks
	// default-branch runs (default true).
	BaselineSecretsBlock bool
	// Fields are the fields this policy sets; the others are inherited from
	// the layer above (the organization policy sets every field).
	Fields []string
	// LockedFields are fields no layer below may loosen (organization and
	// business unit policies only).
	LockedFields []string
	// Reason says why a repository policy differs from what it inherits.
	Reason string
	// ExpiresAt ends a repository policy: after it the repository inherits
	// again (nil: no end).
	ExpiresAt *time.Time
	CreatedBy *shared.ID
	UpdatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DefaultGatePolicy is the built-in policy: new findings of high severity
// or above, or on the KEV list, fail; secrets always fail.
func DefaultGatePolicy() GatePolicy {
	return GatePolicy{ScopeType: ScopeDefault, Enabled: true, Mode: ModeEnforce, FailOnSeverity: "high",
		NewFindingsOnly: true, FailOnKEV: true, AllowRepoPolicy: true, BaselineOnFirstRun: true, BaselineSecretsBlock: true, Fields: slices.Clone(PolicyFields)}
}

// Validate checks a policy. Every error wraps shared.ErrValidation.
func (p *GatePolicy) Validate() error {
	invalid := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", shared.ErrValidation, fmt.Sprintf(format, a...))
	}
	switch p.ScopeType {
	case ScopeTenant:
		if p.ScopeID != nil {
			return invalid("a tenant policy has no scope_id")
		}
	case ScopeBusinessUnit, ScopeRepository:
		if p.ScopeID == nil || p.ScopeID.IsZero() {
			return invalid("scope_id is required for a %s policy", p.ScopeType)
		}
	default:
		return invalid("scope_type must be tenant, business_unit or repository")
	}
	if p.Mode != ModeEnforce && p.Mode != ModeWarn {
		return invalid("mode must be enforce or warn")
	}
	if _, ok := severityRank[p.FailOnSeverity]; (!ok || p.FailOnSeverity == "info") && p.FailOnSeverity != SeverityNone {
		return invalid("fail_on_severity must be critical, high, medium, low or none")
	}
	if p.EPSSThreshold != nil && (*p.EPSSThreshold < 0 || *p.EPSSThreshold > 1) {
		return invalid("epss_threshold must be between 0 and 1")
	}
	if p.BaselineGraceDays != nil && (*p.BaselineGraceDays < 1 || *p.BaselineGraceDays > MaxBaselineGraceDays) {
		return invalid("baseline_grace_days must be between 1 and %d", MaxBaselineGraceDays)
	}
	return p.Modes.Validate()
}

// Strictest merges several policies of the same specificity (a repository
// in more than one business unit) into the strictest of them.
func Strictest(ps []GatePolicy) GatePolicy {
	if len(ps) == 0 {
		return DefaultGatePolicy()
	}
	out := ps[0]
	for _, p := range ps[1:] {
		if p.Mode == ModeEnforce {
			out.Mode = ModeEnforce
		}
		if rank(p.FailOnSeverity) < rank(out.FailOnSeverity) {
			out.FailOnSeverity = p.FailOnSeverity
		}
		if !p.NewFindingsOnly {
			out.NewFindingsOnly = false
		}
		if !p.FixableOnly {
			out.FixableOnly = false
		}
		if p.FailOnKEV {
			out.FailOnKEV = true
		}
		if p.EPSSThreshold != nil && (out.EPSSThreshold == nil || *p.EPSSThreshold < *out.EPSSThreshold) {
			v := *p.EPSSThreshold
			out.EPSSThreshold = &v
		}
		out.Modes = strictestModes(out.Modes, p.Modes)
		out.AllowRepoPolicy = out.AllowRepoPolicy && p.AllowRepoPolicy
		out.BaselineOnFirstRun = out.BaselineOnFirstRun && p.BaselineOnFirstRun
		out.BaselineSecretsBlock = out.BaselineSecretsBlock || p.BaselineSecretsBlock
		if p.BaselineGraceDays != nil && (out.BaselineGraceDays == nil || *p.BaselineGraceDays < *out.BaselineGraceDays) {
			v := *p.BaselineGraceDays
			out.BaselineGraceDays = &v
		}
	}
	return out
}

// rank orders thresholds: a lower rank fails more findings; "none" fails
// none.
func rank(sev string) int {
	if sev == SeverityNone {
		return 99
	}
	if r, ok := severityRank[sev]; ok {
		return r
	}
	return 99
}

// GateOverride lets one commit of one repository pass the gate until it
// expires (break-glass).
type GateOverride struct {
	ID                shared.ID
	TenantID          shared.ID
	RepositoryAssetID shared.ID
	CommitSHA         string
	Reason            string
	CreatedBy         *shared.ID
	// CreatedByEmail is the creator's current email, read from users (empty
	// when the user is gone); never stored with the override.
	CreatedByEmail string
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	RevokedBy      *shared.ID
	CreatedAt      time.Time
}

var commitSHARE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// ValidCommitSHA reports whether s is a full hex commit id (SHA-1 or
// SHA-256). An abbreviated id is refused: an override must cover exactly
// one commit, and a short prefix can be matched by a commit made to fit it.
func ValidCommitSHA(s string) bool { return commitSHARE.MatchString(s) }

// Validate checks a new override. Every error wraps shared.ErrValidation.
func (o *GateOverride) Validate(now time.Time) error {
	o.CommitSHA = strings.ToLower(strings.TrimSpace(o.CommitSHA))
	o.Reason = strings.TrimSpace(o.Reason)
	if !ValidCommitSHA(o.CommitSHA) {
		return fmt.Errorf("%w: commit_sha must be a full commit id (40 or 64 hex characters)", shared.ErrValidation)
	}
	if n := len([]rune(o.Reason)); n < minOverrideReason || n > maxOverrideReason {
		return fmt.Errorf("%w: reason must be %d to %d characters", shared.ErrValidation, minOverrideReason, maxOverrideReason)
	}
	if !o.ExpiresAt.After(now) || o.ExpiresAt.Sub(now) > MaxOverrideTTL+time.Minute {
		return fmt.Errorf("%w: an override lasts at most %s", shared.ErrValidation, MaxOverrideTTL)
	}
	return nil
}

// ActiveAt reports whether the override applies at t.
func (o GateOverride) ActiveAt(t time.Time) bool { return o.RevokedAt == nil && t.Before(o.ExpiresAt) }

// MatchesCommit reports whether the override covers commit sha: the same
// full commit id, nothing else.
func (o GateOverride) MatchesCommit(sha string) bool {
	sha = strings.ToLower(sha)
	return sha != "" && o.CommitSHA != "" && sha == o.CommitSHA
}

// GateInput is everything one evaluation reads.
type GateInput struct {
	Policy       GatePolicy
	PolicySource string
	Findings     []RunFinding
	// NewFingerprints are the findings the change introduced. Nil means the
	// gate could not tell (no baseline) and every finding counts as new.
	NewFingerprints map[string]bool
	BaselineBranch  string
	BaselineKnown   bool
	// BaselineSetAt is when the repository's gate baseline was recorded (nil
	// when it has none).
	BaselineSetAt *time.Time
	// BaselineEstablished: this run recorded the repository's first gate
	// baseline.
	BaselineEstablished bool
	// BaselineDueAt ends the baseline's grace (nil: no end).
	BaselineDueAt *time.Time
	// DefaultBranch: the run is on the repository's default branch, where
	// every open secret blocks.
	DefaultBranch bool
	ScanFailures  int
	// FailedCapabilities are the capabilities the job reported as not clean
	// (FailedCapabilities).
	FailedCapabilities []CapabilityState
	// FindingsOverCap: the run reported more findings than it could record;
	// judging only the recorded ones would miss the rest, so it fails.
	FindingsOverCap bool
	// MissingCapabilities are the capabilities the repository is expected
	// to report (coverage expectation) that the run reported no tool for.
	MissingCapabilities []string
	Override            *GateOverride
	Now                 time.Time
	// FindingURL builds a link to a finding ("" for none).
	FindingURL func(id shared.ID) string
}

// GateReason is one reason in a verdict.
type GateReason struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	FindingID   string `json:"finding_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Title       string `json:"title,omitempty"`
	Severity    string `json:"severity,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	URL         string `json:"url,omitempty"`
	// Mode is "comment" for a reason the policy lists without failing the
	// gate (FindingModeComment); empty for a blocking reason.
	Mode string `json:"mode,omitempty"`
}

// GateSummary counts the run's findings.
type GateSummary struct {
	Evaluated   int `json:"evaluated"`
	New         int `json:"new"`
	PreExisting int `json:"pre_existing"`
	Accepted    int `json:"accepted"`
	Blocking    int `json:"blocking"`
	// Monitored counts findings in monitor mode (recorded, not listed).
	Monitored int `json:"monitored,omitempty"`
}

// GatePolicyView is the policy a verdict used.
type GatePolicyView struct {
	Source          string   `json:"source"`
	Mode            string   `json:"mode"`
	FailOnSeverity  string   `json:"fail_on_severity"`
	NewFindingsOnly bool     `json:"new_findings_only"`
	FailOnKEV       bool     `json:"fail_on_kev"`
	EPSSThreshold   *float64 `json:"epss_threshold,omitempty"`
	FixableOnly     bool     `json:"fixable_only,omitempty"`
	// Modes are the policy's per-capability and per-rule modes, when set.
	Modes *PolicyModes `json:"modes,omitempty"`
}

// GateBaselineView says what the run was compared with.
type GateBaselineView struct {
	Branch string `json:"branch,omitempty"`
	Known  bool   `json:"known"`
	// SetAt is when the repository's gate baseline was recorded; absent
	// when it has none. A default-branch run is compared with it only.
	SetAt *time.Time `json:"set_at,omitempty"`
	// DueAt ends the baseline's grace (its findings' due date): after it they
	// block again. Absent: no end.
	DueAt *time.Time `json:"due_at,omitempty"`
	// Established: this run recorded the repository's first gate baseline
	// (its open findings stopped blocking).
	Established bool `json:"established,omitempty"`
}

// GateOverrideView is the break-glass that let the run pass.
type GateOverrideView struct {
	ID        string    `json:"id"`
	Reason    string    `json:"reason"`
	CreatedBy string    `json:"created_by,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GateVerdict is the result of one evaluation.
type GateVerdict struct {
	Verdict   string            `json:"verdict"`
	WouldFail bool              `json:"would_fail"`
	Reasons   []GateReason      `json:"reasons"`
	Summary   GateSummary       `json:"summary"`
	Policy    GatePolicyView    `json:"policy"`
	Baseline  GateBaselineView  `json:"baseline"`
	Override  *GateOverrideView `json:"override,omitempty"`
}

// Decisions a finding can carry that the gate honors (KnownFinding.Decision).
const (
	DecisionFalsePositive = "false_positive"
	DecisionDuplicate     = "duplicate"
	DecisionAccepted      = "accepted"
	DecisionSuppressed    = "suppressed"
)

// Decision is the decision the gate honors on f at now: a person marked it a
// false positive or a duplicate, accepted its risk (until the acceptance
// expires), or an approved, unexpired suppression rule covers it. "" when
// none: the finding counts.
func Decision(f RunFinding, now time.Time) string {
	switch f.Status {
	case DecisionFalsePositive, DecisionDuplicate:
		return f.Status
	case DecisionAccepted:
		if f.AcceptanceExpiresAt == nil || f.AcceptanceExpiresAt.After(now) {
			return DecisionAccepted
		}
	}
	if f.Suppressed {
		return DecisionSuppressed
	}
	return ""
}

func honored(f RunFinding, now time.Time) bool { return Decision(f, now) != "" }

// KnownFinding tells a CI job that one of the results it uploaded carries a
// decision, so the job leaves it out of its own output (console, SARIF,
// merge request report). Index is the result's position in the uploaded
// report. The job learns nothing about findings it did not report.
// MaxKnownInResponse bounds the decided results an upload response lists
// (about 1 MB of JSON). The rest are counted (KnownTotal), never dropped
// silently: a job that sees fewer shows more of its own results, which is
// safe, and the gate on the platform judges every finding either way. A
// response that grew with the report could exceed what a client reads and
// make a stored report look like a failed upload.
const MaxKnownInResponse = 10_000

type KnownFinding struct {
	Index     int        `json:"index"`
	Decision  string     `json:"decision"`
	FindingID string     `json:"finding_id"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Evaluate decides the verdict. Fail closed: scan failures fail; without a
// baseline every finding counts as new.
func Evaluate(in GateInput) GateVerdict {
	p := in.Policy
	v := GateVerdict{
		Reasons: []GateReason{},
		Policy: GatePolicyView{Source: in.PolicySource, Mode: p.Mode, FailOnSeverity: p.FailOnSeverity, Modes: modesView(p.Modes),
			NewFindingsOnly: p.NewFindingsOnly, FailOnKEV: p.FailOnKEV, EPSSThreshold: p.EPSSThreshold, FixableOnly: p.FixableOnly},
		Baseline: GateBaselineView{Branch: in.BaselineBranch, Known: in.BaselineKnown, SetAt: in.BaselineSetAt,
			Established: in.BaselineEstablished, DueAt: in.BaselineDueAt},
	}
	blocking := 0
	listed := 0
	add := func(r GateReason) {
		blocking++
		if listed < maxReasons {
			v.Reasons = append(v.Reasons, r)
			listed++
		}
	}
	// note lists a reason that does not block.
	note := func(r GateReason) {
		if listed < maxReasons {
			v.Reasons = append(v.Reasons, r)
			listed++
		}
	}
	if in.ScanFailures > 0 {
		add(GateReason{Code: ReasonScanFailure,
			Message: fmt.Sprintf("%d scanner(s) failed to run or to report: the run cannot be judged", in.ScanFailures)})
	}
	for _, c := range in.FailedCapabilities {
		what := c.Name
		if c.Tool != "" {
			what += " (" + c.Tool + ")"
		}
		why := c.State
		if c.Reason != "" {
			why += ": " + c.Reason
		}
		add(GateReason{Code: ReasonCapabilityFailed,
			Message: fmt.Sprintf("the %s scan did not fully reach the platform (%s): the run cannot be judged", what, why)})
	}
	if in.FindingsOverCap {
		add(GateReason{Code: ReasonTooManyFindings,
			Message: fmt.Sprintf("the run reported more than %d findings, more than the gate can judge: the run cannot be judged; split the scan or narrow it", MaxRunFindings)})
	}
	for _, c := range in.MissingCapabilities {
		add(GateReason{Code: ReasonMissingCapability,
			Message: fmt.Sprintf("the repository is expected to be scanned for %s, and this run reported no %s scan: the run cannot be judged", c, c)})
	}
	threshold := rank(p.FailOnSeverity)
	for _, f := range in.Findings {
		v.Summary.Evaluated++
		if honored(f, in.Now) {
			v.Summary.Accepted++
			continue
		}
		isNew := in.NewFingerprints == nil || in.NewFingerprints[f.Fingerprint]
		if isNew {
			v.Summary.New++
		} else {
			v.Summary.PreExisting++
		}
		base := GateReason{FindingID: f.ID.String(), Fingerprint: f.Fingerprint, Title: f.Title, Severity: f.Severity,
			RuleID: f.RuleID, File: f.FilePath, Line: f.StartLine}
		if in.FindingURL != nil && !f.ID.IsZero() {
			base.URL = in.FindingURL(f.ID)
		}
		// A secret in the code fails whatever its age and severity.
		if f.FindingType == "secret" {
			// A new secret always blocks. One already open on the baseline
			// branch blocks the default branch, and is a note on any other
			// branch: a pull request did not add it and cannot remove it from
			// history, so it must not block every pull request.
			if isNew || (in.DefaultBranch && p.BaselineSecretsBlock) {
				r := base
				r.Code, r.Message = ReasonSecret, "a secret is committed to the repository"
				add(r)
			} else {
				note(GateReason{Code: ReasonSecretPreExisting, FindingID: base.FindingID, Fingerprint: base.Fingerprint,
					Title: base.Title, File: base.File, Line: base.Line, URL: base.URL,
					Message: "a secret already committed on the default branch: rotate it; it fails default-branch runs"})
			}
			continue
		}
		if p.NewFindingsOnly && !isNew {
			continue
		}
		// The policy's mode for this finding: block fails the gate, comment
		// lists it without failing, monitor only records it.
		mode := p.Modes.For(f)
		if mode == FindingModeMonitor {
			v.Summary.Monitored++
			continue
		}
		emit := add
		if mode == FindingModeComment {
			emit = func(r GateReason) {
				r.Mode = FindingModeComment
				note(r)
			}
		}
		// No fixed version to move to: listed, not blocking (KEV aside).
		if p.FixableOnly && f.IsVulnerability() && !f.FixAvailable && !(p.FailOnKEV && f.IsInKEV) {
			emit = func(r GateReason) {
				r.Mode = FindingModeComment
				r.Message += " (no fixed version yet)"
				note(r)
			}
		}
		switch {
		case p.FailOnKEV && f.IsInKEV:
			r := base
			r.Code, r.Message = ReasonKEV, "the vulnerability is on the known-exploited (KEV) list"
			emit(r)
		case p.EPSSThreshold != nil && f.EPSSScore != nil && *f.EPSSScore >= *p.EPSSThreshold:
			r := base
			r.Code, r.Message = ReasonEPSS, fmt.Sprintf("EPSS %.3f is at or above %.3f", *f.EPSSScore, *p.EPSSThreshold)
			emit(r)
		case severityRank[strings.ToLower(f.Severity)] >= threshold && threshold != 99:
			r := base
			r.Code, r.Message = ReasonSeverity, fmt.Sprintf("severity %s is at or above %s", strings.ToLower(f.Severity), p.FailOnSeverity)
			emit(r)
		}
	}
	v.Summary.Blocking = blocking
	if p.NewFindingsOnly && !in.BaselineKnown && len(in.Findings) > 0 {
		// Informational: listed after the blocking reasons, not counted.
		msg := fmt.Sprintf("no scan of the baseline branch %q is known: every finding counts as new", in.BaselineBranch)
		if in.DefaultBranch {
			msg = "no gate baseline is recorded for this repository: every finding counts as new until an administrator records one"
		}
		v.Reasons = append(v.Reasons, GateReason{Code: ReasonNoBaseline, Message: msg})
	}
	if in.BaselineEstablished {
		v.Reasons = append(v.Reasons, GateReason{Code: ReasonBaselineEstablished,
			Message: fmt.Sprintf("first run on the default branch: %d existing findings recorded as the gate baseline; from now on only new findings block", v.Summary.PreExisting)})
	}
	fail := blocking > 0
	switch {
	case fail && in.Override != nil && in.Override.ActiveAt(in.Now):
		o := in.Override
		// The verdict goes to CI logs, which may be public: it names no
		// person (the console and the audit log show who created it).
		v.Override = &GateOverrideView{ID: o.ID.String(), Reason: o.Reason, ExpiresAt: o.ExpiresAt}
		v.Reasons = append(v.Reasons, GateReason{Code: ReasonOverride,
			Message: fmt.Sprintf("break-glass by an administrator until %s: %s",
				o.ExpiresAt.UTC().Format(time.RFC3339), o.Reason)})
		v.WouldFail = true
		v.Verdict = VerdictPass
	case fail && p.Mode == ModeWarn:
		v.WouldFail = true
		v.Verdict = VerdictPass
	case fail:
		v.Verdict = VerdictFail
	default:
		v.Verdict = VerdictPass
	}
	return v
}

func modesView(m PolicyModes) *PolicyModes {
	if len(m.Capabilities) == 0 && len(m.Rules) == 0 {
		return nil
	}
	return &m
}
