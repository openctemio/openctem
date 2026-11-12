package cirun

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Coverage is computed per repository x capability, from any executor: a CI
// pipeline whose default-branch runs reported a tool with the capability, or
// a daemon sensor's completed scan of the repository with such a tool. The
// fleet answers "is my sensor alive?"; coverage answers "which repositories
// are not being looked at, and since when?".

// Capability is what a scan looks for in a repository.
type Capability string

const (
	CapabilitySAST    Capability = "sast"
	CapabilitySCA     Capability = "sca"
	CapabilitySecrets Capability = "secrets"
	CapabilityIaC     Capability = "iac"
)

// AllCapabilities lists the repository capabilities, in display order.
func AllCapabilities() []Capability {
	return []Capability{CapabilitySAST, CapabilitySCA, CapabilitySecrets, CapabilityIaC}
}

// IsValid reports whether c is a repository capability.
func (c Capability) IsValid() bool { return slices.Contains(AllCapabilities(), c) }

// ParseCapabilities validates a capability list (de-duplicated, sorted in
// display order). Empty means every capability.
func ParseCapabilities(in []string) ([]Capability, error) {
	seen := map[Capability]bool{}
	for _, s := range in {
		c := Capability(strings.ToLower(strings.TrimSpace(s)))
		if !c.IsValid() {
			return nil, fmt.Errorf("%w: capability %q is not one of sast, sca, secrets, iac", shared.ErrValidation, s)
		}
		seen[c] = true
	}
	out := make([]Capability, 0, len(seen))
	for _, c := range AllCapabilities() {
		if seen[c] {
			out = append(out, c)
		}
	}
	return out, nil
}

// CoverageState is how recently a capability was observed on a repository.
type CoverageState string

const (
	CoverageFresh CoverageState = "fresh"
	CoverageStale CoverageState = "stale"
	CoverageNever CoverageState = "never"
)

// ScanCoverageFreshFor is how long a daemon scan keeps a capability fresh
// (daemon scans have no cadence of their own here).
const ScanCoverageFreshFor = MaxStaleAfter

// CoverageWindow bounds the observations considered: older ones count as
// never (the same horizon as archiving a pipeline).
const CoverageWindow = ArchiveAfter

// Coverage sources.
const (
	SourcePipeline = "ci_pipeline"
	SourceScan     = "scan"
)

// CoverageObservation is the newest sighting of one capability on one
// repository by one source.
type CoverageObservation struct {
	RepositoryAssetID shared.ID
	Capability        Capability
	At                time.Time
	SourceKind        string // SourcePipeline or SourceScan
	// PipelineID is set for a pipeline source.
	PipelineID *shared.ID
	// SourceName is the pipeline's workflow or the scanner's name (label).
	SourceName string
}

// RepositoryRef is a repository asset as coverage lists it.
type RepositoryRef struct {
	ID          shared.ID
	Name        string
	Criticality string
}

// CapabilityCoverage is one capability of one repository.
type CapabilityCoverage struct {
	Capability Capability
	State      CoverageState
	LastAt     *time.Time
	SourceKind string
	PipelineID *shared.ID
	SourceName string
	Expected   bool
}

// RepositoryCoverage is one repository's coverage.
type RepositoryCoverage struct {
	Repository   RepositoryRef
	Capabilities []CapabilityCoverage
	// Expected: an administrator marked the repository as expected to be
	// scanned (for ExpectedCapabilities; all when empty).
	Expected             bool
	ExpectedCapabilities []Capability
	// Covered: at least one capability is fresh.
	Covered bool
	// Gap: an expected capability is not fresh.
	Gap bool
	// Pipelines on the repository (any status).
	Pipelines int
}

// Expectation marks a repository as expected to be covered.
type Expectation struct {
	TenantID          shared.ID
	RepositoryAssetID shared.ID
	Capabilities      []Capability
	CreatedBy         *shared.ID
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ComputeCoverage joins repositories with their observations. A pipeline
// observation is fresh while the pipeline itself is not stale (its own
// cadence) and the pipeline is active; a scan observation is fresh for
// ScanCoverageFreshFor. Observations older than CoverageWindow are ignored.
func ComputeCoverage(repos []RepositoryRef, obs []CoverageObservation, pipelines map[shared.ID]Pipeline,
	expectations map[shared.ID]Expectation, now time.Time, pol StatusPolicy) []RepositoryCoverage {
	type key struct {
		repo shared.ID
		cap  Capability
	}
	best := map[key]CapabilityCoverage{}
	for _, o := range obs {
		if now.Sub(o.At) > CoverageWindow {
			continue
		}
		state := CoverageStale
		switch o.SourceKind {
		case SourcePipeline:
			if o.PipelineID != nil {
				if p, ok := pipelines[*o.PipelineID]; ok {
					st := p.Assess(now, pol).Status
					if !st.IsInactive() && now.Sub(o.At) <= p.StaleAfter() {
						state = CoverageFresh
					}
				}
			}
		case SourceScan:
			if now.Sub(o.At) <= ScanCoverageFreshFor {
				state = CoverageFresh
			}
		}
		k := key{o.RepositoryAssetID, o.Capability}
		cur, ok := best[k]
		at := o.At
		cand := CapabilityCoverage{Capability: o.Capability, State: state, LastAt: &at, SourceKind: o.SourceKind,
			PipelineID: o.PipelineID, SourceName: o.SourceName}
		// Fresh beats stale; between equals, the newer wins.
		if !ok || (cand.State == CoverageFresh && cur.State != CoverageFresh) ||
			(cand.State == cur.State && cur.LastAt != nil && at.After(*cur.LastAt)) {
			best[k] = cand
		}
	}
	perRepo := map[shared.ID]int{}
	for _, p := range pipelines {
		perRepo[p.RepositoryAssetID]++
	}
	out := make([]RepositoryCoverage, 0, len(repos))
	for _, r := range repos {
		rc := RepositoryCoverage{Repository: r, Pipelines: perRepo[r.ID]}
		exp, expected := expectations[r.ID]
		if expected {
			rc.Expected = true
			rc.ExpectedCapabilities = exp.Capabilities
		}
		for _, c := range AllCapabilities() {
			cc, ok := best[key{r.ID, c}]
			if !ok {
				cc = CapabilityCoverage{Capability: c, State: CoverageNever}
			}
			cc.Expected = expected && (len(exp.Capabilities) == 0 || slices.Contains(exp.Capabilities, c))
			if cc.State == CoverageFresh {
				rc.Covered = true
			}
			if cc.Expected && cc.State != CoverageFresh {
				rc.Gap = true
			}
			rc.Capabilities = append(rc.Capabilities, cc)
		}
		out = append(out, rc)
	}
	return out
}

// CoverageSummary counts repositories for the header.
type CoverageSummary struct {
	Repositories int
	Covered      int
	Uncovered    int
	Expected     int
	Gaps         int
	// UncoveredByCriticality counts repositories with no fresh capability.
	UncoveredByCriticality map[string]int
	// FreshByCapability counts repositories with the capability fresh.
	FreshByCapability map[Capability]int
}

// Summarize counts a coverage listing.
func Summarize(rows []RepositoryCoverage) CoverageSummary {
	s := CoverageSummary{UncoveredByCriticality: map[string]int{}, FreshByCapability: map[Capability]int{}}
	for _, c := range AllCapabilities() {
		s.FreshByCapability[c] = 0
	}
	for _, r := range rows {
		s.Repositories++
		if r.Covered {
			s.Covered++
		} else {
			s.Uncovered++
			s.UncoveredByCriticality[nonEmptyStr(r.Repository.Criticality, "unknown")]++
		}
		if r.Expected {
			s.Expected++
		}
		if r.Gap {
			s.Gaps++
		}
		for _, c := range r.Capabilities {
			if c.State == CoverageFresh {
				s.FreshByCapability[c.Capability]++
			}
		}
	}
	return s
}

func nonEmptyStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// criticalityRank orders repositories most critical first.
var criticalityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}

// SortCoverage puts gaps first, then uncovered, then by criticality and name.
func SortCoverage(rows []RepositoryCoverage) {
	rank := func(r RepositoryCoverage) int {
		switch {
		case r.Gap:
			return 0
		case !r.Covered:
			return 1
		}
		return 2
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		ca, okA := criticalityRank[a.Repository.Criticality]
		cb, okB := criticalityRank[b.Repository.Criticality]
		if !okA {
			ca = 5
		}
		if !okB {
			cb = 5
		}
		if ca != cb {
			return ca < cb
		}
		return a.Repository.Name < b.Repository.Name
	})
}

// ---------------------------------------------------------------- drift --

// TemplateUse is one version of a template and the pipelines on it.
type TemplateUse struct {
	Version   string
	Pipelines []shared.ID
	LastRunAt *time.Time
}

// TemplateDrift is a reusable workflow (or external configuration) and the
// versions its pipelines run. Current is the version of the pipeline that
// ran it most recently; the others have drifted.
type TemplateDrift struct {
	Template string
	Current  string
	Versions []TemplateUse
	Drifted  int
	Total    int
}

// ComputeTemplateDrift groups active pipelines by template.
func ComputeTemplateDrift(pipes []Pipeline, now time.Time, pol StatusPolicy) []TemplateDrift {
	groups := map[string]map[string]*TemplateUse{}
	for i := range pipes {
		p := &pipes[i]
		if p.TemplateRef == "" || p.Assess(now, pol).Status.IsInactive() {
			continue
		}
		t, v := TemplatePath(p.TemplateRef), TemplateVersion(p.TemplateRef)
		if groups[t] == nil {
			groups[t] = map[string]*TemplateUse{}
		}
		u := groups[t][v]
		if u == nil {
			u = &TemplateUse{Version: v}
			groups[t][v] = u
		}
		u.Pipelines = append(u.Pipelines, p.ID)
		if p.LastRunAt != nil && (u.LastRunAt == nil || p.LastRunAt.After(*u.LastRunAt)) {
			at := *p.LastRunAt
			u.LastRunAt = &at
		}
	}
	out := make([]TemplateDrift, 0, len(groups))
	for t, versions := range groups {
		d := TemplateDrift{Template: t}
		var newest *time.Time
		for _, u := range versions {
			d.Versions = append(d.Versions, *u)
			d.Total += len(u.Pipelines)
			if u.LastRunAt != nil && (newest == nil || u.LastRunAt.After(*newest)) {
				newest, d.Current = u.LastRunAt, u.Version
			}
		}
		sort.Slice(d.Versions, func(i, j int) bool { return len(d.Versions[i].Pipelines) > len(d.Versions[j].Pipelines) })
		for _, u := range d.Versions {
			if u.Version != d.Current {
				d.Drifted += len(u.Pipelines)
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Template < out[j].Template })
	return out
}

// --------------------------------------------------------------- alerts --

// AlertKind is a signal worth a notification. Never one per run.
type AlertKind string

const (
	AlertScheduleMissed     AlertKind = "schedule_missed"
	AlertCoverageRegression AlertKind = "coverage_regression"
	AlertGateFailing        AlertKind = "gate_failing"
	AlertRunnerOutdated     AlertKind = "runner_outdated"
	// AlertTokenRefusals: a burst of refused CI token exchanges in the
	// tenant (verified tokens only; the subject is the tenant).
	AlertTokenRefusals AlertKind = "token_refusals"
)

// A tenant whose CI token exchanges were refused TokenRefusalBurst times
// within TokenRefusalWindow raises AlertTokenRefusals.
const (
	TokenRefusalBurst  = 20
	TokenRefusalWindow = 30 * time.Minute
)

// Alert is one condition that holds now, for one subject (a pipeline, or a
// repository for coverage regression).
type Alert struct {
	Kind              AlertKind
	SubjectID         shared.ID
	PipelineID        *shared.ID
	RepositoryAssetID shared.ID
	Repository        string
	Workflow          string
	Detail            map[string]any
}

// Key identifies an alert for de-duplication.
func (a Alert) Key() string { return string(a.Kind) + ":" + a.SubjectID.String() }

// EvaluateAlerts returns the alert conditions that hold now. Revoked,
// retired and archived pipelines raise nothing; a repository regresses when
// it has active pipelines but none of them is fresh any more.
func EvaluateAlerts(pipes []Pipeline, now time.Time, pol StatusPolicy) []Alert {
	var out []Alert
	type repoState struct {
		name       string
		active     int
		fresh      int
		pipelineID shared.ID
	}
	repos := map[shared.ID]*repoState{}
	for i := range pipes {
		p := &pipes[i]
		a := p.Assess(now, pol)
		if a.Status.IsInactive() {
			continue
		}
		id := p.ID
		base := Alert{SubjectID: p.ID, PipelineID: &id, RepositoryAssetID: p.RepositoryAssetID,
			Repository: p.RepositoryName, Workflow: p.WorkflowPath}
		if a.Scheduled && a.Freshness == FreshnessStale {
			al := base
			al.Kind = AlertScheduleMissed
			al.Detail = map[string]any{"schedule_interval": p.ScheduleInterval.String(), "last_run_at": p.LastRunAt}
			out = append(out, al)
		}
		if a.Gate == GateFailing {
			al := base
			al.Kind = AlertGateFailing
			al.Detail = map[string]any{"last_verdict_at": p.LastDefaultVerdictAt}
			out = append(out, al)
		}
		if slices.Contains(a.HealthReasons, ReasonOutdated) {
			al := base
			al.Kind = AlertRunnerOutdated
			al.Detail = map[string]any{"sensor_version": p.SensorVersion, "min_version": pol.MinVersion}
			out = append(out, al)
		}
		rs := repos[p.RepositoryAssetID]
		if rs == nil {
			rs = &repoState{name: p.RepositoryName, pipelineID: p.ID}
			repos[p.RepositoryAssetID] = rs
		}
		rs.active++
		if a.Freshness == FreshnessFresh || a.Freshness == FreshnessRunning {
			rs.fresh++
		}
	}
	for repoID, rs := range repos {
		if rs.active > 0 && rs.fresh == 0 {
			out = append(out, Alert{Kind: AlertCoverageRegression, SubjectID: repoID, RepositoryAssetID: repoID,
				Repository: rs.name, Detail: map[string]any{"pipelines": rs.active}})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// AlertState is an alert currently firing (its notification was sent).
type AlertState struct {
	SubjectID shared.ID
	Kind      AlertKind
	FiredAt   time.Time
}

// MinRetireReason and MaxRetireReason bound a retirement's reason.
const (
	MinRetireReason = 10
	MaxRetireReason = 2000
)
