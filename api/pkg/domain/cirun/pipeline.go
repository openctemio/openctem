package cirun

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A pipeline is the logical identity of a CI scanner: one workflow file of
// one repository. It is listed in the fleet as a sensor in runner mode, but
// it is not a sensor row: it holds no key, has no heartbeat, joins no zone
// and is never dispatched. Its runs are the executions.

// ErrPipelineNotFound is a pipeline that does not exist in the tenant (or
// is outside the caller's data scope).
var ErrPipelineNotFound = fmt.Errorf("%w: CI pipeline not found", shared.ErrNotFound)

// ErrPipelineCap refuses a new pipeline when the tenant or the trust
// configuration already has the most it may have.
var ErrPipelineCap = fmt.Errorf("%w: CI pipeline limit reached", shared.ErrConflict)

// Caps on pipelines. A trust configuration for "acme/**" could otherwise let
// every repository of an organization create rows.
const (
	DefaultMaxPipelinesPerTenant      = 2000
	DefaultMaxPipelinesPerTrustConfig = 1000
)

// Limits on the self-declared labels of a run (the runner chooses them; they
// are display data only and never part of an identity).
const (
	MaxToolsPerRun    = 20
	maxToolNameLen    = 64
	maxWorkflowPath   = 500
	maxDisplayNameLen = 255
	maxTemplateRefLen = 500
)

// LegacyRepoIDPrefix marks a pipeline backfilled from runs recorded before
// pipelines existed (no repository id); the next verified run adopts it.
const LegacyRepoIDPrefix = "legacy:"

// GitLabDefaultConfigPath is the configuration file of a GitLab project
// whose token names none.
const GitLabDefaultConfigPath = ".gitlab-ci.yml"

// ToolLabel is a tool a run reported (from its report's tool block).
type ToolLabel struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Pipeline is one CI pipeline of a tenant.
type Pipeline struct {
	ID                shared.ID
	TenantID          shared.ID
	Provider          Provider
	Issuer            string
	ExternalRepoID    string
	WorkflowPath      string
	RepositoryAssetID shared.ID
	TrustConfigID     *shared.ID
	// Display names, refreshed by each non-fork run.
	RepositoryName string
	WorkflowName   string
	// TemplateRef is the reusable workflow or external configuration the
	// pipeline runs ("org/security/.github/workflows/scan.yml@refs/tags/v2"),
	// TemplateSHA its commit; empty when the workflow is the repository's own.
	TemplateRef   string
	TemplateSHA   string
	DefaultBranch string

	FirstRunAt    *time.Time
	LastRunAt     *time.Time
	LastRunID     *shared.ID
	LastRunStatus string
	// LastForkRunAt is the newest fork run. Fork runs never make a pipeline
	// fresh and never set its default-branch gate.
	LastForkRunAt *time.Time
	RunsCount     int

	LastDefaultRunAt     *time.Time
	LastDefaultVerdict   string
	LastDefaultVerdictAt *time.Time
	LastPRVerdict        string
	LastPRVerdictAt      *time.Time
	LastScanFailures     *int
	SensorVersion        string
	Tools                []ToolLabel

	// MedianInterval is the median time between non-fork runs and
	// ScheduleInterval the median time between scheduled runs (0: unknown).
	MedianInterval   time.Duration
	ScheduleInterval time.Duration

	RevokedAt *time.Time
	// RetiredAt: an administrator retired the pipeline (its sole findings
	// were closed as "source retired"). The next verified run revives it.
	RetiredAt    *time.Time
	RetiredBy    *shared.ID
	RetireReason string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IsLegacy reports whether the pipeline was backfilled without a repository
// id.
func (p *Pipeline) IsLegacy() bool { return strings.HasPrefix(p.ExternalRepoID, LegacyRepoIDPrefix) }

// PipelineKey is a pipeline's identity: immutable provider ids from verified
// claims. The branch, the job and the tools are not part of it.
type PipelineKey struct {
	Provider       Provider
	Issuer         string
	ExternalRepoID string
	WorkflowPath   string
}

// RefusePipelineIdentity refuses a token whose claims cannot identify a
// pipeline (no repository id, or no usable workflow path).
const RefusePipelineIdentity = "pipeline_identity"

// PipelineKeyFromClaims derives the pipeline key from verified claims:
//
//   - GitHub, GitLab: the numeric repository or project id and the workflow
//     file;
//   - Azure Pipelines: the project id and "pipelines/<definition id>";
//   - CircleCI: the project id and "pipelines/<pipeline definition id>"
//     (".circleci/config.yml" when the token names no definition);
//   - Bitbucket: the repository UUID and "bitbucket-pipelines.yml";
//   - Jenkins: an id derived from the repository claim and the job's full
//     name (without the branch of a multibranch job).
func PipelineKeyFromClaims(provider Provider, issuer string, c Claims) (PipelineKey, *Refusal) {
	repoID, wp := strings.TrimSpace(c.RepositoryID), ""
	switch provider {
	case ProviderGitHub, ProviderGitLab:
		if repoID == "" || len(repoID) > 64 || !isDigits(repoID) {
			return PipelineKey{}, refuse(RefusePipelineIdentity, "the token carries no numeric repository or project id")
		}
		wp = WorkflowPath(provider, c.Repository, c.Workflow)
	case ProviderAzureDevOps:
		repoID = c.ProjectID
		if isDigits(c.DefinitionID) && len(c.DefinitionID) <= 20 {
			wp = "pipelines/" + c.DefinitionID
		}
	case ProviderCircleCI:
		repoID = c.ProjectID
		switch {
		case uuidRE.MatchString(c.DefinitionID):
			wp = "pipelines/" + c.DefinitionID
		case c.DefinitionID == "":
			wp = CircleCIDefaultConfigPath
		}
	case ProviderBitbucket:
		wp = BitbucketConfigPath
	case ProviderJenkins:
		if len(repoID) != 32 {
			repoID = ""
		}
		wp = cleanWorkflowPath(c.Workflow)
	}
	if provider != ProviderGitHub && provider != ProviderGitLab && provider != ProviderJenkins && !uuidRE.MatchString(repoID) {
		return PipelineKey{}, refuse(RefusePipelineIdentity, "the token carries no project or repository id")
	}
	if repoID == "" {
		return PipelineKey{}, refuse(RefusePipelineIdentity, "the token carries no repository")
	}
	if wp == "" {
		return PipelineKey{}, refuse(RefusePipelineIdentity, "the token carries no usable workflow path")
	}
	return PipelineKey{Provider: provider, Issuer: issuer, ExternalRepoID: repoID, WorkflowPath: wp}, nil
}

// Pipeline paths of providers whose token names no workflow file.
const (
	CircleCIDefaultConfigPath = ".circleci/config.yml"
	BitbucketConfigPath       = "bitbucket-pipelines.yml"
)

// WorkflowPath is the workflow file of a job, relative to its repository and
// without the ref: GitHub "owner/name/.github/workflows/scan.yml@refs/heads/x"
// gives ".github/workflows/scan.yml", GitLab
// "gitlab.example.com/group/project//.gitlab-ci.yml@refs/heads/x" gives
// ".gitlab-ci.yml". The repository prefix is dropped so a renamed repository
// keeps its pipelines. "" when the claim is unusable.
func WorkflowPath(provider Provider, repository, claim string) string {
	claim = refPath(strings.TrimSpace(claim))
	var p string
	switch provider {
	case ProviderGitHub:
		prefix := strings.ToLower(strings.Trim(repository, "/")) + "/"
		switch {
		case prefix != "/" && strings.HasPrefix(strings.ToLower(claim), prefix):
			p = claim[len(prefix):]
		case strings.Contains(claim, "/.github/"):
			p = claim[strings.Index(claim, "/.github/")+1:]
		default:
			p = claim
		}
	case ProviderGitLab:
		switch {
		case claim == "":
			p = GitLabDefaultConfigPath
		case strings.Contains(claim, "//"):
			p = claim[strings.Index(claim, "//")+2:]
		default:
			p = claim
		}
	}
	return cleanWorkflowPath(p)
}

// cleanWorkflowPath keeps a relative path of printable characters without
// "." or ".." segments, at most maxWorkflowPath long.
func cleanWorkflowPath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" || len(p) > maxWorkflowPath {
		return ""
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return ""
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return ""
		}
	}
	return p
}

// Template returns the pipeline's template from the claims: the reusable
// workflow a GitHub job runs (job_workflow_ref, when it is not the workflow
// itself) or the external configuration a GitLab project uses
// (ci_config_ref_uri, when it lives in another project). Empty when the
// workflow is the repository's own.
func Template(provider Provider, issuer string, c Claims) (ref, sha string) {
	switch provider {
	case ProviderGitHub:
		job := strings.TrimSpace(c.JobWorkflowRef)
		if job == "" || refPath(job) == refPath(c.Workflow) {
			return "", ""
		}
		ref = job
	case ProviderGitLab:
		uri := strings.TrimSpace(c.Workflow)
		project, _, ok := strings.Cut(refPath(uri), "//")
		if !ok || strings.EqualFold(project, IssuerHost(issuer)+"/"+c.Repository) {
			return "", ""
		}
		ref = uri
	}
	return truncateLabel(SanitizeLabel(ref, maxTemplateRefLen), maxTemplateRefLen), sanitizeHex(c.JobWorkflowSHA)
}

// TemplatePath is a template reference without its "@ref".
func TemplatePath(ref string) string { return refPath(ref) }

// TemplateVersion is the "@ref" part of a template reference.
func TemplateVersion(ref string) string {
	if p := refPath(ref); len(p) < len(ref) {
		return ref[len(p)+1:]
	}
	return ""
}

// refPath drops the "@ref" of a workflow reference. The ref starts at the
// first "@refs/" (a branch name may itself contain "@"), else at the last
// "@" (a short ref such as "@v2").
func refPath(s string) string {
	if i := strings.Index(s, "@refs/"); i >= 0 {
		return s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return s[:i]
	}
	return s
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func sanitizeHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 64 {
		return ""
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return s
}

// SanitizeLabel makes a self-declared or claimed string safe to store and
// show: control and format characters are dropped, whitespace collapsed,
// and the result capped at max bytes (on a rune boundary).
func SanitizeLabel(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == unicode.ReplacementChar:
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return truncateLabel(b.String(), max)
}

func truncateLabel(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// SanitizeTools turns the tools a run's reports declared into stored labels:
// names lower case from [a-z0-9._-] (anything else dropped), versions in the
// sensor version form, de-duplicated by name (last wins), sorted, at most
// MaxToolsPerRun.
func SanitizeTools(in []ToolLabel) []ToolLabel {
	byName := map[string]string{}
	for _, t := range in {
		name := sanitizeToolName(t.Name)
		if name == "" {
			continue
		}
		if _, seen := byName[name]; !seen && len(byName) >= MaxToolsPerRun {
			continue
		}
		byName[name] = sensor.NormalizeVersion(t.Version)
	}
	out := make([]ToolLabel, 0, len(byName))
	for n, v := range byName {
		out = append(out, ToolLabel{Name: n, Version: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sanitizeToolName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() >= maxToolNameLen {
			break
		}
	}
	return b.String()
}

// ------------------------------------------------------------------ status --

// Freshness is how recent a pipeline's runs are against its cadence. A
// pipeline is never "offline": it runs when its repository says so.
type Freshness string

const (
	FreshnessRunning  Freshness = "running"
	FreshnessFresh    Freshness = "fresh"
	FreshnessStale    Freshness = "stale"
	FreshnessArchived Freshness = "archived"
	// FreshnessNever: the pipeline exists (backfilled, or only fork runs)
	// but has no run of its own.
	FreshnessNever Freshness = "never"
)

// Gate is the last verdict of the pipeline's default branch.
type Gate string

const (
	GatePassing Gate = "passing"
	GateFailing Gate = "failing"
	GateNone    Gate = "none"
)

// Health is how the last run executed.
type Health string

const (
	HealthOK Health = "ok"
	// HealthDegraded: scanner errors in the last evaluated run, or a runner
	// older than the minimum supported sensor release.
	HealthDegraded Health = "degraded"
	HealthUnknown  Health = "unknown"
)

// Health reasons.
const (
	ReasonScannerErrors = "scanner_errors"
	ReasonOutdated      = "outdated_runner"
)

// PipelineStatus is the combined badge, in severity order.
type PipelineStatus string

const (
	PipelineRetired  PipelineStatus = "retired"
	PipelineRevoked  PipelineStatus = "revoked"
	PipelineFailing  PipelineStatus = "failing"
	PipelineDegraded PipelineStatus = "degraded"
	PipelineStale    PipelineStatus = "stale"
	PipelineRunning  PipelineStatus = "running"
	PipelineFresh    PipelineStatus = "fresh"
	PipelineNever    PipelineStatus = "never"
	PipelineArchived PipelineStatus = "archived"
)

// AllPipelineStatuses lists every combined status (for counts and filters).
func AllPipelineStatuses() []PipelineStatus {
	return []PipelineStatus{PipelineRetired, PipelineRevoked, PipelineFailing, PipelineDegraded, PipelineStale, PipelineRunning,
		PipelineFresh, PipelineNever, PipelineArchived}
}

// IsInactive reports the statuses hidden by default (archived, revoked,
// retired, never ran). Hidden is not deleted: the rows, runs and findings
// stay.
func (s PipelineStatus) IsInactive() bool {
	return s == PipelineArchived || s == PipelineRevoked || s == PipelineNever || s == PipelineRetired
}

// Freshness thresholds.
const (
	// RunningWindow: a run still running after this is not shown as running
	// (it can no longer get a token; MaxRunContinuation in the service).
	RunningWindow = 6 * time.Hour
	MinStaleAfter = 7 * 24 * time.Hour
	MaxStaleAfter = 30 * 24 * time.Hour
	// ArchiveAfter idle archives a pipeline; its next run revives it.
	ArchiveAfter = 90 * 24 * time.Hour
	// MissedScheduleCycles: a scheduled pipeline is stale after missing
	// this many cycles.
	MissedScheduleCycles = 2
	scheduleGrace        = time.Hour
)

// StatusPolicy is the release channel a runner's version is judged against.
type StatusPolicy struct {
	LatestVersion string
	MinVersion    string
}

// Assessment is a pipeline's computed status.
type Assessment struct {
	Status        PipelineStatus
	Freshness     Freshness
	Gate          Gate
	PRGate        Gate
	Health        Health
	HealthReasons []string
	// StaleAfter is how long after its last run the pipeline turns stale.
	StaleAfter    time.Duration
	StaleAt       *time.Time
	VersionStatus sensor.VersionStatus
	// Scheduled: the pipeline has scheduled runs, so its cadence is the
	// schedule's.
	Scheduled bool
}

// StaleAfter is the pipeline's expected-cadence threshold: two missed
// cycles of its schedule when it has scheduled runs; otherwise three times
// its median run interval, at least MinStaleAfter and at most MaxStaleAfter.
func (p *Pipeline) StaleAfter() time.Duration {
	if p.ScheduleInterval > 0 {
		d := MissedScheduleCycles*p.ScheduleInterval + scheduleGrace
		return min(d, ArchiveAfter)
	}
	d := 3 * p.MedianInterval
	return max(MinStaleAfter, min(d, MaxStaleAfter))
}

// Assess computes the pipeline's status at now. The three dimensions
// (freshness, gate, execution health) are kept apart; Status is the one
// badge, in severity order failing > degraded > stale > running/fresh.
// Archived and revoked override everything (they are hidden by default).
func (p *Pipeline) Assess(now time.Time, pol StatusPolicy) Assessment {
	a := Assessment{Gate: gateOf(p.LastDefaultVerdict), PRGate: gateOf(p.LastPRVerdict), StaleAfter: p.StaleAfter(),
		Scheduled: p.ScheduleInterval > 0, Health: HealthUnknown}
	a.VersionStatus = sensor.ClassifyVersion(p.SensorVersion, pol.LatestVersion, pol.MinVersion)

	switch {
	case p.LastRunAt == nil:
		a.Freshness = FreshnessNever
	case p.LastRunStatus == StatusRunning && now.Sub(*p.LastRunAt) < RunningWindow:
		a.Freshness = FreshnessRunning
	case now.Sub(*p.LastRunAt) > ArchiveAfter:
		a.Freshness = FreshnessArchived
	case now.Sub(*p.LastRunAt) > a.StaleAfter:
		a.Freshness = FreshnessStale
	default:
		a.Freshness = FreshnessFresh
	}
	if p.LastRunAt != nil {
		at := p.LastRunAt.Add(a.StaleAfter)
		a.StaleAt = &at
	}

	if p.LastScanFailures != nil || p.SensorVersion != "" {
		a.Health = HealthOK
	}
	if p.LastScanFailures != nil && *p.LastScanFailures > 0 {
		a.HealthReasons = append(a.HealthReasons, ReasonScannerErrors)
	}
	if a.VersionStatus == sensor.VersionUnsupported {
		a.HealthReasons = append(a.HealthReasons, ReasonOutdated)
	}
	if len(a.HealthReasons) > 0 {
		a.Health = HealthDegraded
	}

	switch {
	case p.RetiredAt != nil:
		a.Status = PipelineRetired
	case p.RevokedAt != nil:
		a.Status = PipelineRevoked
	case a.Freshness == FreshnessArchived:
		a.Status = PipelineArchived
	case a.Freshness == FreshnessNever:
		a.Status = PipelineNever
	case a.Gate == GateFailing:
		a.Status = PipelineFailing
	case a.Health == HealthDegraded:
		a.Status = PipelineDegraded
	case a.Freshness == FreshnessStale:
		a.Status = PipelineStale
	case a.Freshness == FreshnessRunning:
		a.Status = PipelineRunning
	default:
		a.Status = PipelineFresh
	}
	return a
}

func gateOf(verdict string) Gate {
	switch verdict {
	case VerdictPass:
		return GatePassing
	case VerdictFail:
		return GateFailing
	}
	return GateNone
}

// IsScheduleEvent reports whether a run was started by a schedule (GitHub
// event_name, GitLab pipeline_source).
func IsScheduleEvent(event string) bool { return event == "schedule" }

// PipelineFilter narrows a pipeline listing. Pipelines are capped per
// tenant, so the listing is filtered after the status is computed.
type PipelineFilter struct {
	RepositoryAssetID *shared.ID
	TrustConfigID     *shared.ID
	Provider          string
	// DataScope limits the listing to pipelines on repositories the user may
	// see (RFC-050).
	DataScope *shared.DataScope
}

// PipelineBranch summarizes the runs of one branch of a pipeline.
type PipelineBranch struct {
	Branch          string
	IsDefaultBranch bool
	Runs            int
	LastRunAt       time.Time
	LastVerdict     string
}

// GatePoint is one evaluated default-branch run, for the gate trend.
type GatePoint struct {
	RunID       shared.ID
	Verdict     string
	CommitSHA   string
	EvaluatedAt time.Time
}

// MaxPipelineBranches caps the branch summary of one pipeline.
const MaxPipelineBranches = 100

// MaxListedPipelines bounds one listing (the tenant cap can be raised by
// configuration; the listing never returns more than this).
const MaxListedPipelines = 10000
