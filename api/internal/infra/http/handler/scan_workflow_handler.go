package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/pagination"

	"github.com/go-chi/chi/v5"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// ScanWorkflowHandler handles HTTP requests for scan workflows.
type ScanWorkflowHandler struct {
	// scopeSnapshots reads a run's scope snapshot (RFC-065 §9).
	scopeSnapshots RunScopeSnapshots
	service        *scanrun.Service
	validator      *validator.Validator
	logger         *logger.Logger
	// taskLogs reads a run task's logs (nil: GET .../tasks/{task_id}/logs
	// answers an empty log).
	taskLogs taskLogReader
	// placement explains why a queued task waits (nil: not found).
	placement taskPlacementExplainer
	// findingScope checks the finding of a run about a finding (retest).
	findingScope runFindingScope
	// runLookup reads a run for the access check (the service when unset).
	runLookup runReader
	// users names the people who started runs (nil: no names).
	users user.Repository
	// runEvents reads the run timeline (nil: an empty timeline).
	runEvents command.EventReader
	// readiness computes ?include=readiness (nil: never included).
	readiness WorkflowReadinessFunc
}

// NewScanWorkflowHandler creates a new ScanWorkflowHandler.
func NewScanWorkflowHandler(service *scanrun.Service, v *validator.Validator, log *logger.Logger) *ScanWorkflowHandler {
	return &ScanWorkflowHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "scan_workflow"),
	}
}

// --- Template Request/Response Types ---

// CreateTemplateRequest represents the request body for creating a scan workflow.
type CreateTemplateRequest struct {
	Name        string                       `json:"name" validate:"required,min=1,max=255"`
	Description string                       `json:"description" validate:"max=1000"`
	Settings    *ScanWorkflowSettingsRequest `json:"settings"`
	Tags        []string                     `json:"tags" validate:"max=10,dive,max=50"`
	Steps       []CreateStepRequest          `json:"steps" validate:"max=50,dive"`
}

// ScanWorkflowSettingsRequest represents template settings in the request.
type ScanWorkflowSettingsRequest struct {
	MaxParallelSteps int    `json:"max_parallel_steps" validate:"min=0,max=10"`
	FailFast         bool   `json:"fail_fast"`
	TimeoutSeconds   int    `json:"timeout_seconds" validate:"min=0,max=86400"`
	SensorPreference string `json:"sensor_preference" validate:"omitempty,oneof=auto tenant platform"`
	// DeltaGating: heavy chained stages (templates, crawl, screenshots,
	// service detection) take only the assets new, changed or due since the
	// previous run of the same scan. Omitted on update: unchanged.
	DeltaGating *bool `json:"delta_gating,omitempty"`
	// ContinueOnFailedDependency: a step whose dependency failed, was
	// skipped or timed out still runs on the seeds and on what its other
	// predecessors produced. Omitted on update: unchanged.
	ContinueOnFailedDependency *bool `json:"continue_on_failed_dependency,omitempty"`
	// StageBarrier: every chained step waits for its predecessors to
	// finish instead of taking their results task by task (stage
	// streaming). Omitted on update: unchanged.
	StageBarrier *bool `json:"stage_barrier,omitempty"`
}

// UIPositionRequest represents a visual position in the workflow builder.
type UIPositionRequest struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// CreateStepRequest represents a step in the create template request.
// Capabilities are optional - if not provided and tool is specified, they will be derived from the tool.
type CreateStepRequest struct {
	// ID is the id of the existing step this entry is, when the request saves
	// a whole scan workflow (PUT): the step is updated in place and keeps its run
	// history. Optional; an id that is not one of the scan workflow's steps (for
	// example a client-side temporary id) makes the entry a new step.
	ID           string             `json:"id,omitempty" validate:"max=64"`
	StepKey      string             `json:"step_key" validate:"required,min=1,max=100"`
	Name         string             `json:"name" validate:"required,min=1,max=255"`
	Description  string             `json:"description" validate:"max=1000"`
	Order        int                `json:"order"`
	UIPosition   *UIPositionRequest `json:"ui_position"`
	Tool         string             `json:"tool" validate:"max=100"`
	Capabilities []string           `json:"capabilities" validate:"omitempty,max=10,dive,max=50"`
	// PreferTools are the tools to try, in order, for the step's capability
	// when no tool is pinned. Each must implement the capability.
	PreferTools       []string               `json:"prefer_tools" validate:"omitempty,max=5,dive,max=100"`
	Config            map[string]interface{} `json:"config"`
	TimeoutSeconds    int                    `json:"timeout_seconds"`
	DependsOn         []string               `json:"depends_on" validate:"max=20,dive,max=50"`
	Condition         *StepConditionRequest  `json:"condition"`
	MaxRetries        int                    `json:"max_retries"`
	RetryDelaySeconds int                    `json:"retry_delay_seconds"`
	// RunPolicy is how the step runs at each depth (min_depth, per-depth
	// standard params and target cap) and whether it waits for a tool
	// (optional). Omitted on a step update: unchanged.
	RunPolicy *scanworkflow.RunPolicy `json:"run_policy,omitempty"`
}

// StepConditionRequest represents a step condition in the request.
type StepConditionRequest struct {
	Type  string `json:"type" validate:"oneof=always never asset_type expression step_result"`
	Value string `json:"value" validate:"max=500"`
}

// TemplateResponse represents the response for a scan workflow.
type TemplateResponse struct {
	ID               string                       `json:"id"`
	TenantID         string                       `json:"tenant_id"`
	Name             string                       `json:"name"`
	Description      string                       `json:"description,omitempty"`
	Version          int                          `json:"version"`
	IsActive         bool                         `json:"is_active"`
	IsSystemTemplate bool                         `json:"is_system_template"`
	Settings         ScanWorkflowSettingsResponse `json:"settings"`
	Tags             []string                     `json:"tags,omitempty"`
	Steps            []StepResponse               `json:"steps"`
	// Readiness is whether the workflow can run for the caller's
	// organization now, with ?include=readiness.
	Readiness       *WorkflowReadinessResponse `json:"readiness,omitempty"`
	UIStartPosition *UIPositionResponse        `json:"ui_start_position,omitempty"`
	UIEndPosition   *UIPositionResponse        `json:"ui_end_position,omitempty"`
	CreatedAt       string                     `json:"created_at"`
	UpdatedAt       string                     `json:"updated_at"`
	// RetiredAt is set when the workflow was deleted while it had runs (it
	// is read-only and kept for their history).
	RetiredAt string `json:"retired_at,omitempty"`
	// IsRetired: a system workflow retired on purpose. It cannot start new
	// scans or be copied; SupersededBy names its replacement, when it has one.
	IsRetired    bool         `json:"is_retired"`
	SupersededBy *WorkflowRef `json:"superseded_by,omitempty"`
	// BasedOnRetired is set on a tenant copy made from a retired system workflow.
	BasedOnRetired *RetiredSourceResponse `json:"based_on_retired,omitempty"`
}

// WorkflowRef points at another workflow.
type WorkflowRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RetiredSourceResponse is the retired system workflow a copy was made from.
type RetiredSourceResponse struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	SupersededBy *WorkflowRef `json:"superseded_by,omitempty"`
}

func supersededRef(t *scanworkflow.Workflow) *WorkflowRef {
	if t.SupersededBy == nil {
		return nil
	}
	return &WorkflowRef{ID: t.SupersededBy.String(), Name: t.SupersededByName}
}

// ScanWorkflowSettingsResponse represents template settings in the response.
type ScanWorkflowSettingsResponse struct {
	MaxParallelSteps int    `json:"max_parallel_steps"`
	FailFast         bool   `json:"fail_fast"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	SensorPreference string `json:"sensor_preference"`
	// DeltaGating: heavy chained stages run only on new, changed or due assets.
	DeltaGating bool `json:"delta_gating"`
	// ContinueOnFailedDependency: dependents of a failed step still run.
	ContinueOnFailedDependency bool `json:"continue_on_failed_dependency"`
	// StageBarrier: chained steps wait for their predecessors to finish
	// (no stage streaming).
	StageBarrier bool `json:"stage_barrier"`
}

// UIPositionResponse represents a visual position in the workflow builder response.
type UIPositionResponse struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// StepResponse represents a step in the response.
type StepResponse struct {
	ID           string             `json:"id"`
	StepKey      string             `json:"step_key"`
	Name         string             `json:"name"`
	Description  string             `json:"description,omitempty"`
	Order        int                `json:"order"`
	UIPosition   UIPositionResponse `json:"ui_position"`
	Tool         string             `json:"tool,omitempty"`
	Capabilities []string           `json:"capabilities"`
	// PreferTools are the tools to try, in order, when no tool is pinned.
	PreferTools []string `json:"prefer_tools"`
	// ToolSelection is how the step picks its tool: pin (tool), prefer
	// (prefer_tools) or auto (any implementation of its capability).
	ToolSelection     string                 `json:"tool_selection" enums:"auto,prefer,pin"`
	Config            map[string]interface{} `json:"config,omitempty"`
	TimeoutSeconds    int                    `json:"timeout_seconds,omitempty"`
	DependsOn         []string               `json:"depends_on,omitempty"`
	Condition         *StepConditionResponse `json:"condition,omitempty"`
	MaxRetries        int                    `json:"max_retries"`
	RetryDelaySeconds int                    `json:"retry_delay_seconds"`
	// RunPolicy is how the step runs at each depth and whether it waits for
	// a tool; absent when the step sets none.
	RunPolicy *scanworkflow.RunPolicy `json:"run_policy,omitempty"`
}

// StepConditionResponse represents a step condition in the response.
type StepConditionResponse struct {
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// --- Run Request/Response Types ---

// RunResponse represents the response for a scan run.
type RunResponse struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	ScanWorkflowID string `json:"scan_workflow_id"`
	// Intensity is the probe ceiling the run started with:
	// passive, active or intrusive; absent for a run without one.
	Intensity string  `json:"intensity,omitempty" enums:"passive,active,intrusive"`
	AssetID   *string `json:"asset_id,omitempty"`
	ScanID    *string `json:"scan_id,omitempty"`
	// ScanName names the run's scan (list rows only; empty when the scan was
	// deleted).
	ScanName string `json:"scan_name,omitempty"`
	// ManagedBy names the platform policy that owns the run's scan, so the
	// run is read-only for people: coverage (continuous coverage), enrichment
	// or web_verify. Absent for a scan a person owns (list rows only).
	ManagedBy       string  `json:"managed_by,omitempty" enums:"coverage,enrichment,web_verify"`
	ScanProfileID   *string `json:"scan_profile_id,omitempty"`
	TriggerType     string  `json:"trigger_type"`
	TriggeredBy     string  `json:"triggered_by,omitempty"`
	TriggeredByName string  `json:"triggered_by_name,omitempty"` // display name, when triggered_by is a user id
	// Trigger is who or what started the run, in one shape for every kind.
	Trigger        *RunTrigger `json:"trigger,omitempty"`
	Status         string      `json:"status"`
	StartedAt      *string     `json:"started_at,omitempty"`
	CompletedAt    *string     `json:"completed_at,omitempty"`
	TotalSteps     int         `json:"total_steps"`
	CompletedSteps int         `json:"completed_steps"`
	FailedSteps    int         `json:"failed_steps"`
	SkippedSteps   int         `json:"skipped_steps"`
	TotalFindings  int         `json:"total_findings"`
	// UnreachableTargetCount and SkippedTargetCount are the targets the
	// run's sensors could not reach, or skipped by their local policy. They
	// never change the run's status (a run with only these completes).
	UnreachableTargetCount int `json:"unreachable_target_count,omitempty"`
	SkippedTargetCount     int `json:"skipped_target_count,omitempty"`
	// NoLongerResolveCount is how many of the skipped targets are names that
	// no longer resolve (informational, never an error).
	NoLongerResolveCount int                            `json:"no_longer_resolve_count,omitempty"`
	QualityGateResult    *scanprofile.QualityGateResult `json:"quality_gate_result,omitempty"`
	StepRuns             []StepRunResponse              `json:"scan_run_steps,omitempty"`
	ErrorMessage         string                         `json:"error_message,omitempty"`
	// RefusalCode says why a blocked run was refused (status blocked only),
	// e.g. ALL_TARGETS_EXCLUDED, SCAN_WINDOW_NEVER_OPENS, NO_SENSOR_AVAILABLE.
	RefusalCode string `json:"refusal_code,omitempty"`
	// Kind is what the run is: scan, quick, retest, validation, test,
	// connector or system.
	Kind string `json:"kind"`
	// Subject names what a run that executes no scan workflow is about,
	// e.g. {"finding_id", "retest_id"} for a retest.
	Subject map[string]any `json:"subject,omitempty"`
	// Result is what a completed run concluded when that is more than
	// "done": a retest that was inconclusive or found the exposure at
	// another path. The run is completed (the tool did its work); the
	// console words the result from its code.
	Result *RunResult `json:"result,omitempty"`
	// ScanWorkflowVersion is the saved version of the scan workflow this run
	// executes (settings and steps as the run started), SpecDigest its
	// digest. Absent for runs without a workflow and runs from before
	// versions.
	ScanWorkflowVersion int    `json:"scan_workflow_version,omitempty"`
	SpecDigest          string `json:"spec_digest,omitempty"`
	CreatedAt           string `json:"created_at"`
	// ScheduledFor is the schedule occurrence this run serves (scheduled runs only).
	ScheduledFor *string `json:"scheduled_for,omitempty"`
	// DeadlineAt is when the run is settled if it is still open.
	DeadlineAt *string `json:"deadline_at,omitempty"`
	// DeadlineReason is which policy set DeadlineAt: scan_max_duration,
	// workflow_max_duration, platform_cap, work_estimate (moved at a claim to
	// the time the claimed work needs), or legacy (set before reasons
	// were recorded).
	DeadlineReason string `json:"deadline_reason,omitempty"`
	// UnfinishedTargetCount is how many targets were still open when the run
	// was settled at its deadline; the next scheduled run plans them first.
	UnfinishedTargetCount int                      `json:"unfinished_target_count,omitempty"`
	FilteringResult       *FilteringResultResponse `json:"filtering_result,omitempty"`
	Dispatch              *RunDispatchResponse     `json:"dispatch,omitempty"`
	// TaskSummary counts the run's tasks (the commands it dispatched) by
	// status. Present on list rows and on the run, once it has tasks.
	TaskSummary *RunTaskSummaryResponse `json:"task_summary,omitempty"`
	// Tasks lists the run's tasks (GET /scan-runs/{id} only).
	Tasks []RunTaskResponse `json:"tasks,omitempty"`
	// TasksTruncated is true when the run has more tasks than Tasks lists.
	TasksTruncated bool `json:"tasks_truncated,omitempty"`
	// TasksNextCursor continues the task list after Tasks
	// (GET /scan-runs/{id}/tasks?cursor=) when TasksTruncated.
	TasksNextCursor string `json:"tasks_next_cursor,omitempty"`
	// WindowWaits: the targets that had to wait for their scan windows when
	// the run started, and until when.
	WindowWaits *RunWindowWaitsResponse `json:"window_waits,omitempty"`
}

// RunWindowWaitsResponse lists the targets of a run that wait for their
// scan windows (at most 50 listed; waiting_count counts all).
type RunWindowWaitsResponse struct {
	WaitingCount int                  `json:"waiting_count"`
	Waiting      []scansvc.TargetWait `json:"waiting"`
	NextOpenAt   *time.Time           `json:"next_open_at,omitempty"`
}

// toRunWindowWaits reads the waits the trigger records in the run context.
func toRunWindowWaits(rc map[string]any) *RunWindowWaitsResponse {
	raw, ok := rc[scansvc.RunContextKeyWindowWaits]
	if !ok || raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var out RunWindowWaitsResponse
	if json.Unmarshal(b, &out) != nil || out.WaitingCount == 0 {
		return nil
	}
	return &out
}

// RunTaskPageResponse is one page of a run's tasks.
type RunTaskPageResponse struct {
	Data []RunTaskResponse `json:"data"`
	// NextCursor continues after Data; absent on the last page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// RunTaskSummaryResponse counts a run's tasks by status (RFC-046 §4.1).
type RunTaskSummaryResponse struct {
	Total     int `json:"total"`
	Queued    int `json:"queued"`
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Canceled  int `json:"canceled"`
	// Sensors is how many distinct sensors claimed one of the tasks.
	Sensors int `json:"sensors"`
}

// RunTaskResponse is one task of a run: one command, one tool, a slice of
// targets (counted, not listed), one sensor attempt at a time.
type RunTaskResponse struct {
	ID        string  `json:"id"`
	StepRunID *string `json:"scan_run_step_id,omitempty"`
	StepKey   string  `json:"step_key,omitempty"`
	Tool      string  `json:"tool,omitempty"`
	// Status is queued, running, completed, failed or canceled.
	Status     string  `json:"status"`
	SensorID   *string `json:"sensor_id,omitempty"`
	SensorName string  `json:"sensor_name,omitempty"`
	// Platform is true when a shared platform sensor runs the task; it is
	// never named.
	Platform     bool    `json:"platform,omitempty"`
	Targets      int     `json:"targets"`
	Attempts     int     `json:"attempts"`
	CreatedAt    string  `json:"created_at"`
	StartedAt    *string `json:"started_at,omitempty"`
	CompletedAt  *string `json:"completed_at,omitempty"`
	ErrorMessage string  `json:"error_message,omitempty"`
	// SkippedTargets are the targets the sensor's local policy skipped in a
	// task that completed on the rest (at most 20; sensor-supplied text,
	// show as plain text). SkippedTargetsTotal counts all of them.
	SkippedTargets      []RunTaskSkippedTarget `json:"skipped_targets,omitempty"`
	SkippedTargetsTotal int                    `json:"skipped_targets_total,omitempty"`
	// CoverageGaps are the hosts the sensor could not fully cover in a task
	// that completed (at most 20; sensor-supplied text, show as plain
	// text). CoverageGapsTotal counts all of them.
	CoverageGaps      []RunTaskCoverageGap `json:"coverage_gaps,omitempty"`
	CoverageGapsTotal int                  `json:"coverage_gaps_total,omitempty"`
	// EgressRefusedTargets counts the targets of a completed task the
	// sensor's network confinement kept the tool from reaching: they were
	// not scanned (show "could not reach", never "found nothing").
	EgressRefusedTargets int `json:"egress_refused_targets,omitempty"`
	// GuardRefusedTargets counts the targets of the task the sensor's
	// target guard refused (blocked or unresolvable addresses, unsafe
	// targets): never run. Sensor-supplied, bounded by targets.
	GuardRefusedTargets int `json:"guard_refused_targets,omitempty"`
	// WindowHold: a queued task waits for a scan window (why, until when,
	// or never).
	WindowHold *scanwindow.Hold `json:"window_hold,omitempty"`
	// WaitingOnHosts: a queued task waits while another task of the
	// organization scans one of its hosts (the placement explains which).
	WaitingOnHosts bool `json:"waiting_on_hosts,omitempty"`
	// HostWait says, for a task waiting on its hosts, how many are held,
	// by which task, and how many of its targets can start.
	HostWait *RunTaskHostWait `json:"host_wait,omitempty"`
	// Progress is a running task's finished targets as its sensor last
	// reported them, and when that count last grew.
	Progress *RunTaskProgress `json:"progress,omitempty"`
	// BudgetSeconds is the task's expected time; StallSeconds how long it
	// may finish no target before it is re-queued as stalled. 0: none.
	BudgetSeconds int `json:"budget_seconds,omitempty"`
	StallSeconds  int `json:"stall_seconds,omitempty"`
	// WithheldReason is, for a task no sensor took (queued, or failed
	// without a claim), the placement code of the last time a sensor's
	// dispatch gate withheld it (grant_credentials, intensity, ...). The
	// sensor is never named.
	WithheldReason string `json:"withheld_reason,omitempty"`
	// ContentPins is what the task's job read: the packs (name, version,
	// digest) and the lists generated for it (source, lines, sha256, and
	// the organization lists with their versions).
	ContentPins *scanrundom.ContentPins `json:"content_pins,omitempty"`
}

// RunTaskCoverageGap is one host a sensor could not fully cover, and why:
// reason is breaker_open (the host stopped answering), rate_floor (it kept
// pushing back at the lowest rate), blocked (it blocked the scan) or
// proxy_unavailable (the scan's proxy failed).
type RunTaskCoverageGap struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
	// Edge (challenged or blocked) and Vendor (an edge protection's id
	// token) say that an edge protection answered in the host's place;
	// only on a blocked gap, shown as text.
	Edge   string `json:"edge,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

// RunTaskSkippedTarget is one target a sensor skipped, and why: reason is
// unresolvable, wildcard_pattern, denied_by_policy, invalid_target or
// refused; rule is the sensor's policy rule.
type RunTaskSkippedTarget struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
	Rule   string `json:"rule,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func toRunTaskSummaryResponse(s scanrundom.TaskSummary) *RunTaskSummaryResponse {
	if s.Total == 0 {
		return nil
	}
	return &RunTaskSummaryResponse{
		Total: s.Total, Queued: s.Queued, Running: s.Running, Completed: s.Completed,
		Failed: s.Failed, Canceled: s.Canceled, Sensors: s.Sensors,
	}
}

// RunTaskProgress is a running task's progress.
type RunTaskProgress struct {
	Done           int     `json:"done"`
	Total          int     `json:"total"`
	LastProgressAt *string `json:"last_progress_at,omitempty"`
}

func toRunTaskResponses(tasks []scanrundom.Task) []RunTaskResponse {
	out := make([]RunTaskResponse, 0, len(tasks))
	for _, t := range tasks {
		r := RunTaskResponse{
			ID: t.ID.String(), StepKey: t.StepKey, Tool: t.Tool, Status: string(t.Status),
			SensorName: t.SensorName, Platform: t.Platform, Targets: t.Targets, Attempts: t.Attempts,
			CreatedAt: t.CreatedAt.Format(time.RFC3339), ErrorMessage: platformText(t.Platform, t.ErrorMessage),
			SkippedTargetsTotal: t.SkippedTotal, WindowHold: t.WindowHold, CoverageGapsTotal: t.CoverageGapsTotal,
			WaitingOnHosts: t.WaitingOnHosts, EgressRefusedTargets: t.EgressRefusedTargets,
			GuardRefusedTargets: t.GuardRefusedTargets, WithheldReason: t.WithheldReason, ContentPins: t.ContentPins,
		}
		for _, sk := range t.Skipped {
			r.SkippedTargets = append(r.SkippedTargets, RunTaskSkippedTarget(sk))
		}
		for _, g := range t.CoverageGaps {
			r.CoverageGaps = append(r.CoverageGaps, RunTaskCoverageGap{Host: g.Host, Reason: g.Reason,
				Detail: platformText(t.Platform, g.Detail), Edge: g.Edge, Vendor: g.Vendor})
		}
		if t.StepRunID != nil {
			v := t.StepRunID.String()
			r.StepRunID = &v
		}
		if t.SensorID != nil {
			v := t.SensorID.String()
			r.SensorID = &v
		}
		if t.StartedAt != nil {
			v := t.StartedAt.Format(time.RFC3339)
			r.StartedAt = &v
		}
		if t.CompletedAt != nil {
			v := t.CompletedAt.Format(time.RFC3339)
			r.CompletedAt = &v
		}
		r.BudgetSeconds, r.StallSeconds = t.BudgetSeconds, t.StallSeconds
		if p := t.Progress; p != nil {
			r.Progress = &RunTaskProgress{Done: p.Done, Total: p.Total}
			if p.LastAt != nil {
				v := p.LastAt.Format(time.RFC3339)
				r.Progress.LastProgressAt = &v
			}
		}
		out = append(out, r)
	}
	return out
}

// RunDispatchResponse is what a scan run dispatched: targets resolved and
// excluded by scope, every target not scanned and why, and the scan-zone
// routing (RFC-023). Absent for runs that recorded none of it.
type RunDispatchResponse struct {
	ResolvedTargets int `json:"resolved_targets"`
	ExcludedTargets int `json:"excluded_targets"`
	// Excluded lists the targets the organization's exclusions left out
	// (whole, or a range cut around excluded addresses) with the matching
	// rules, at most 50.
	Excluded         []RunExcludedTarget  `json:"excluded,omitempty"`
	Warnings         []string             `json:"warnings,omitempty"`
	UncoveredTargets []RunUncoveredTarget `json:"uncovered_targets,omitempty"`
	ZoneRouting      *RunZoneRouting      `json:"zone_routing,omitempty"`
	// SensorRouting is where the run's commands were queued: "tenant" or
	// "platform" (shared platform sensors), decided at trigger time.
	SensorRouting string `json:"sensor_routing,omitempty"`
	// TargetExpansion is what each dynamic target selector (*.example.com,
	// an inventory-mode CIDR) added from the inventory when the run started.
	TargetExpansion []RunTargetExpansion `json:"target_expansion,omitempty"`
	// WillScan is how many targets the run dispatched; Skipped groups every
	// other target by reason (docs/architecture/scan-targets.md, "Skipped
	// targets"). Absent on runs started before the groups were recorded.
	WillScan *int                `json:"will_scan,omitempty"`
	Skipped  []scansvc.SkipGroup `json:"skipped,omitempty"`
}

// RunTargetExpansion is what one selector added to a run.
type RunTargetExpansion struct {
	Selector string   `json:"selector"`
	Kind     string   `json:"kind"` // wildcard | cidr
	Matched  int      `json:"matched"`
	Capped   bool     `json:"capped,omitempty"`
	Sample   []string `json:"sample,omitempty"`
}

// RunExcludedTarget is a target exclusions left out of a run.
type RunExcludedTarget struct {
	Target string `json:"target"`
	// Rules are the organization's exclusions that matched.
	Rules []RunExclusionRule `json:"rules,omitempty"`
	// Cut: a range dispatched without its excluded addresses
	// (RemovedAddresses of them).
	Cut              bool   `json:"cut,omitempty"`
	RemovedAddresses uint64 `json:"removed_addresses,omitempty"`
}

// RunExclusionRule is one matching exclusion.
type RunExclusionRule struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
}

// RunUncoveredTarget is a target the run did not scan.
type RunUncoveredTarget struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// RunZoneRouting summarizes how a run's targets were routed to scan zones.
type RunZoneRouting struct {
	Jobs             int            `json:"jobs"`
	TargetsPerJob    int            `json:"targets_per_job"`
	UnzonedTargets   int            `json:"unzoned_targets"`
	UncoveredTargets int            `json:"uncovered_targets"`
	ZoneID           string         `json:"zone_id,omitempty"` // workflow runs: the one zone the run is bound to
	Zones            []RunZoneRoute `json:"zones,omitempty"`
}

// RunZoneRoute is one zone's share of a run.
type RunZoneRoute struct {
	ZoneID     string   `json:"zone_id"`
	ZoneName   string   `json:"zone_name"`
	Targets    int      `json:"targets"`
	Jobs       int      `json:"jobs"`
	QueuedJobs int      `json:"queued_jobs"` // waiting for a healthy sensor of the zone
	SensorIDs  []string `json:"sensor_ids"`  // sensors the jobs were pinned to
}

// FilteringResultResponse represents smart filtering result in API response.
type FilteringResultResponse struct {
	TotalAssets          int                  `json:"total_assets"`
	ScannedAssets        int                  `json:"scanned_assets"`
	SkippedAssets        int                  `json:"skipped_assets"`
	UnclassifiedAssets   int                  `json:"unclassified_assets"`
	CompatibilityPercent float64              `json:"compatibility_percent"`
	ScannedByType        map[string]int       `json:"scanned_by_type,omitempty"`
	SkippedByType        map[string]int       `json:"skipped_by_type,omitempty"`
	SkipReasons          []SkipReasonResponse `json:"skip_reasons,omitempty"`
	WasFiltered          bool                 `json:"was_filtered"`
	ToolName             string               `json:"tool_name,omitempty"`
	SupportedTargets     []string             `json:"supported_targets,omitempty"`
}

// SkipReasonResponse explains why assets of a certain type were skipped.
type SkipReasonResponse struct {
	AssetType string `json:"asset_type"`
	Count     int    `json:"count"`
	Reason    string `json:"reason"`
}

// StepRunResponse represents a step run in the response.
type StepRunResponse struct {
	ID string `json:"id"`
	// StepID is empty once the step was removed from the scan workflow; the step
	// run keeps its key, name and tool.
	StepID   string `json:"step_id,omitempty"`
	StepKey  string `json:"step_key"`
	StepName string `json:"step_name,omitempty"`
	Tool     string `json:"tool,omitempty"`
	// Capability is the versioned capability the step run ran.
	Capability   string  `json:"capability,omitempty"`
	Status       string  `json:"status"`
	StartedAt    *string `json:"started_at,omitempty"`
	CompletedAt  *string `json:"completed_at,omitempty"`
	ErrorMessage string  `json:"error_message,omitempty"`
	ErrorCode    string  `json:"error_code,omitempty"`
	// ErrorClass groups the code by what can fix it: config, scope,
	// placement, policy, transient, tool, timeout or canceled.
	ErrorClass    string `json:"error_class,omitempty"`
	Attempt       int    `json:"attempt"`
	MaxAttempts   int    `json:"max_attempts"`
	FindingsCount int    `json:"findings_count"`
}

// --- Template Handlers ---

// CreateTemplate handles POST /api/v1/scan-workflows/templates
func (h *ScanWorkflowHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req CreateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	input := scanrun.CreateTemplateInput{
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Settings:    toSettings(req.Settings),
		Tags:        req.Tags,
		CreatedBy:   userID,
	}

	stepInputs := make([]scanrun.AddStepInput, 0, len(req.Steps))
	for i, stepReq := range req.Steps {
		stepInput := toAddStepInput(tenantID, "", stepReq)
		stepInput.ID = "" // a new pipeline has no existing steps
		if stepInput.Order == 0 {
			stepInput.Order = i + 1
		}
		stepInputs = append(stepInputs, stepInput)
	}

	// Validate every step before anything is written: the template and its
	// steps are separate inserts, so a step rejected after the template was
	// created used to leave an empty scan workflow behind — and a retry then hit
	// "Scan workflow already exists".
	if err := h.service.ValidateSteps(r.Context(), stepInputs); err != nil {
		h.handleServiceError(w, err)
		return
	}

	template, err := h.service.CreateTemplate(scanWorkflowAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	steps, err := h.service.ReplaceSteps(scanWorkflowAuditCtx(r), scanrun.ReplaceStepsInput{
		TenantID:   tenantID,
		TemplateID: template.ID.String(),
		Steps:      stepInputs,
	})
	if err != nil {
		// A step can still fail past validation. Remove the half-built
		// template rather than leave it behind.
		if delErr := h.service.DeleteTemplate(scanWorkflowAuditCtx(r), tenantID, template.ID.String()); delErr != nil {
			h.logger.Error("failed to remove pipeline template after a step was rejected",
				"template_id", template.ID.String(), "error", delErr)
		}
		h.handleServiceError(w, err)
		return
	}
	template.Steps = steps

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// GetTemplate handles GET /api/v1/scan-workflows/{id}
// @Summary      Get a scan workflow
// @Description  The scan workflow with its steps. include=readiness adds whether it can run for the caller's organization now (ready, waiting, ci_only, blocked) and why, per step.
// @Tags         Scan workflows
// @Produce      json
// @Param        id       path   string  true   "Scan workflow ID"
// @Param        include  query  string  false  "readiness"
// @Success      200  {object}  TemplateResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-workflows/{id} [get]
func (h *ScanWorkflowHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	template, err := h.service.GetTemplate(r.Context(), tenantID, templateID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Get steps for template
	steps, err := h.service.GetSteps(r.Context(), templateID)
	if err != nil {
		h.logger.Warn("failed to get steps for template", "error", logger.SanitizeError(err), "template_id", logger.SanitizeValue(templateID))
	} else {
		template.Steps = steps
	}

	out := toTemplateResponse(template)
	if src, err := h.service.RetiredSource(r.Context(), tenantID, template); err != nil {
		h.logger.Warn("failed to read the retired source of a copy", "error", logger.SanitizeError(err), "template_id", logger.SanitizeValue(templateID))
	} else if src != nil {
		out.BasedOnRetired = &RetiredSourceResponse{ID: src.ID.String(), Name: src.Name, SupersededBy: supersededRef(src)}
	}
	if wantsReadiness(r) {
		h.attachReadiness(r.Context(), tenantID, []*scanworkflow.Workflow{template}, []*TemplateResponse{out})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// ListTemplates handles GET /api/v1/scan-workflows
// @Summary      List scan workflows
// @Description  The organization's scan workflows and the system templates, with their steps. include=readiness adds, for each, whether it can run for the caller's organization now and why, in one computation.
// @Tags         Scan workflows
// @Produce      json
// @Param        is_active  query  bool    false  "Active only"
// @Param        search     query  string  false  "Name search"
// @Param        include_retired query bool false  "Also list retired system workflows (hidden by default)"
// @Param        include    query  string  false  "readiness"
// @Param        page       query  int     false  "Page"
// @Param        per_page   query  int     false  "Page size"
// @Success      200  {object}  pagination.Result[TemplateResponse]
// @Security     BearerAuth
// @Router       /scan-workflows [get]
func (h *ScanWorkflowHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	var isActive *bool
	if activeStr := r.URL.Query().Get("is_active"); activeStr != "" {
		active := activeStr == queryParamTrue
		isActive = &active
	}

	page, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	input := scanrun.ListTemplatesInput{
		TenantID: tenantID,
		IsActive: isActive,
		Tags:     parseQueryArray(r.URL.Query().Get("tags")),
		Search:   r.URL.Query().Get("search"),
		Page:     page.Page,
		PerPage:  page.PerPage,

		IncludeRetired: r.URL.Query().Get("include_retired") == queryParamTrue,
	}

	result, err := h.service.ListTemplates(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := pagination.Map(result, toTemplateResponse)
	if wantsReadiness(r) {
		h.attachReadiness(r.Context(), tenantID, result.Data, resp.Data)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdateTemplateRequest represents the request body for updating a template.
type UpdateTemplateRequest struct {
	Name            string                       `json:"name" validate:"omitempty,min=1,max=255"`
	Description     string                       `json:"description" validate:"max=1000"`
	Settings        *ScanWorkflowSettingsRequest `json:"settings"`
	Tags            []string                     `json:"tags" validate:"max=10,dive,max=50"`
	IsActive        *bool                        `json:"is_active"`
	Steps           []CreateStepRequest          `json:"steps" validate:"max=50,dive"`
	UIStartPosition *UIPositionRequest           `json:"ui_start_position"`
	UIEndPosition   *UIPositionRequest           `json:"ui_end_position"`
}

// UpdateTemplate handles PUT /api/v1/scan-workflows/templates/{id}
func (h *ScanWorkflowHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Steps first: the save validates every step and is refused as a whole
	// (nothing changes) while a run of the scan workflow is active, so a refused
	// save does not leave the template's other fields half applied.
	var steps []*scanworkflow.Step
	if req.Steps != nil {
		stepInputs := make([]scanrun.AddStepInput, 0, len(req.Steps))
		for _, stepReq := range req.Steps {
			stepInputs = append(stepInputs, toAddStepInput(tenantID, templateID, stepReq))
		}
		var err error
		steps, err = h.service.ReplaceSteps(scanWorkflowAuditCtx(r), scanrun.ReplaceStepsInput{
			TenantID:   tenantID,
			TemplateID: templateID,
			Steps:      stepInputs,
		})
		if err != nil {
			h.handleStepError(w, err)
			return
		}
	}

	input := scanrun.UpdateTemplateInput{
		TenantID:        tenantID,
		TemplateID:      templateID,
		Name:            req.Name,
		Description:     req.Description,
		Settings:        toSettings(req.Settings),
		Tags:            req.Tags,
		IsActive:        req.IsActive,
		UIStartPosition: toUIPosition(req.UIStartPosition),
		UIEndPosition:   toUIPosition(req.UIEndPosition),
	}
	if req.Settings != nil {
		input.DeltaGating = req.Settings.DeltaGating
		input.ContinueOnFailedDependency = req.Settings.ContinueOnFailedDependency
		input.StageBarrier = req.Settings.StageBarrier
	}

	template, err := h.service.UpdateTemplate(scanWorkflowAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	if steps == nil {
		steps, _ = h.service.GetSteps(r.Context(), templateID)
	}
	template.Steps = steps

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// writeGraphInvalid writes a refused workflow graph as 422 with every
// node- and edge-anchored issue in details; false when err is not one.
func writeGraphInvalid(w http.ResponseWriter, err error) bool {
	var ge *scanrun.GraphInvalidError
	if !errors.As(err, &ge) {
		return false
	}
	apierror.ValidationFailed("The workflow is not valid", ge.Report).WriteJSON(w)
	return true
}

// ValidateScanWorkflowRequest is a draft scan workflow's steps.
type ValidateScanWorkflowRequest struct {
	Steps []CreateStepRequest `json:"steps" validate:"max=50,dive"`
}

// ScanWorkflowGraphIssueResponse is one problem of a workflow graph, anchored to
// a node (step key) or an edge (from → to).
type ScanWorkflowGraphIssueResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Node    string `json:"node,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	// Adapter is the capability that would connect an incompatible edge.
	Adapter string `json:"adapter,omitempty"`
	// Field is the step field the issue is about (tool, capabilities, config, step_key).
	Field string `json:"field,omitempty"`
	// Fix says how to resolve the issue.
	Fix string `json:"fix,omitempty"`
}

// ScanWorkflowGraphValidationResponse is the outcome of a graph check. Errors
// refuse a save; warnings do not.
type ScanWorkflowGraphValidationResponse struct {
	Valid    bool                             `json:"valid"`
	Errors   []ScanWorkflowGraphIssueResponse `json:"errors"`
	Warnings []ScanWorkflowGraphIssueResponse `json:"warnings"`
}

// ValidateScanWorkflow handles POST /api/v1/scan-workflows/verify
// @Summary      Validate a scan workflow graph
// @Description  Checks a draft scan workflow's steps as a save would (step keys, tools, settings, then the graph against the capability contracts: typed connections, cycles, missing steps, intrusive steps fed derived targets, size) and reports every issue, anchored to its step and field. errors block a save; warnings (no online sensor offers a tool now) do not. A draft with issues is still a 200. Stores nothing.
// @Tags         Scan workflows
// @Accept       json
// @Produce      json
// @Param        body  body      ValidateScanWorkflowRequest  true  "Draft steps"
// @Success      200   {object}  ScanWorkflowGraphValidationResponse
// @Failure      400   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-workflows/verify [post]
func (h *ScanWorkflowHandler) ValidateScanWorkflow(w http.ResponseWriter, r *http.Request) {
	var req ValidateScanWorkflowRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	inputs := make([]scanrun.AddStepInput, 0, len(req.Steps))
	for _, st := range req.Steps {
		inputs = append(inputs, toAddStepInput(tenantID, "", st))
	}
	rep, err := h.service.CheckSteps(r.Context(), scanrun.ValidateGraphInput{TenantID: tenantID, Steps: inputs})
	if err != nil {
		h.handleStepError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toGraphValidationResponse(rep))
}

func toGraphIssueResponse(is stage.GraphIssue) ScanWorkflowGraphIssueResponse {
	return ScanWorkflowGraphIssueResponse{
		Code: is.Code, Message: is.Message, Node: is.Node,
		From: is.From, To: is.To, Adapter: string(is.Adapter),
		Field: is.Field, Fix: is.Fix,
	}
}

// toAddStepInput maps one step of a request to the service input.
func toAddStepInput(tenantID, templateID string, req CreateStepRequest) scanrun.AddStepInput {
	in := scanrun.AddStepInput{
		TenantID:          tenantID,
		TemplateID:        templateID,
		ID:                req.ID,
		StepKey:           req.StepKey,
		Name:              req.Name,
		Description:       req.Description,
		Order:             req.Order,
		Tool:              req.Tool,
		Capabilities:      req.Capabilities,
		PreferTools:       req.PreferTools,
		Config:            req.Config,
		TimeoutSeconds:    req.TimeoutSeconds,
		DependsOn:         req.DependsOn,
		Condition:         toCondition(req.Condition),
		MaxRetries:        req.MaxRetries,
		RetryDelaySeconds: req.RetryDelaySeconds,
		RunPolicy:         req.RunPolicy,
	}
	if req.UIPosition != nil {
		in.UIPositionX = &req.UIPosition.X
		in.UIPositionY = &req.UIPosition.Y
	}
	return in
}

// DeleteTemplate handles DELETE /api/v1/scan-workflows/templates/{id}
func (h *ScanWorkflowHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteTemplate(scanWorkflowAuditCtx(r), tenantID, templateID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ActivateTemplate handles POST /api/v1/scan-workflows/{id}/activate
func (h *ScanWorkflowHandler) ActivateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	isActive := true
	input := scanrun.UpdateTemplateInput{
		TenantID:   tenantID,
		TemplateID: templateID,
		IsActive:   &isActive,
	}

	template, err := h.service.UpdateTemplate(scanWorkflowAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// DeactivateTemplate handles POST /api/v1/scan-workflows/{id}/deactivate
func (h *ScanWorkflowHandler) DeactivateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	isActive := false
	input := scanrun.UpdateTemplateInput{
		TenantID:   tenantID,
		TemplateID: templateID,
		IsActive:   &isActive,
	}

	template, err := h.service.UpdateTemplate(scanWorkflowAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// CloneTemplateRequest represents the request body for cloning a template.
type CloneTemplateRequest struct {
	Name string `json:"name" validate:"required,min=1,max=255"`
}

// CloneTemplate handles POST /api/v1/scan-workflows/{id}/clone
func (h *ScanWorkflowHandler) CloneTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CloneTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := scanrun.CloneTemplateInput{
		TenantID:   tenantID,
		TemplateID: templateID,
		NewName:    req.Name,
		ClonedBy:   userID,
	}

	template, err := h.service.CloneTemplate(scanWorkflowAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// --- Step Handlers ---

// AddStep handles POST /api/v1/scan-workflows/templates/{id}/steps
func (h *ScanWorkflowHandler) AddStep(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req CreateStepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := scanrun.AddStepInput{
		TenantID:          tenantID,
		TemplateID:        templateID,
		StepKey:           req.StepKey,
		Name:              req.Name,
		Description:       req.Description,
		Order:             req.Order,
		Tool:              req.Tool,
		Capabilities:      req.Capabilities,
		Config:            req.Config,
		TimeoutSeconds:    req.TimeoutSeconds,
		DependsOn:         req.DependsOn,
		Condition:         toCondition(req.Condition),
		MaxRetries:        req.MaxRetries,
		RetryDelaySeconds: req.RetryDelaySeconds,
	}
	if req.UIPosition != nil {
		input.UIPositionX = &req.UIPosition.X
		input.UIPositionY = &req.UIPosition.Y
	}

	step, err := h.service.AddStep(scanWorkflowAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toStepResponse(step))
}

// UpdateStepRequest represents the request body for updating a step.
type UpdateStepRequest struct {
	Name              string                 `json:"name" validate:"omitempty,min=1,max=255"`
	Description       string                 `json:"description" validate:"max=1000"`
	Order             int                    `json:"order"`
	UIPosition        *UIPositionRequest     `json:"ui_position"`
	Tool              string                 `json:"tool" validate:"max=100"`
	Capabilities      []string               `json:"capabilities" validate:"max=10,dive,max=50"`
	Config            map[string]interface{} `json:"config"`
	TimeoutSeconds    int                    `json:"timeout_seconds"`
	DependsOn         []string               `json:"depends_on" validate:"max=20,dive,max=50"`
	Condition         *StepConditionRequest  `json:"condition"`
	MaxRetries        int                    `json:"max_retries"`
	RetryDelaySeconds int                    `json:"retry_delay_seconds"`
}

// UpdateStep handles PUT /api/v1/scan-workflows/templates/{id}/steps/{stepId}
func (h *ScanWorkflowHandler) UpdateStep(w http.ResponseWriter, r *http.Request) {
	stepID := chi.URLParam(r, "stepId")
	tenantID := middleware.GetTenantID(r.Context())
	templateID := chi.URLParam(r, "id")

	var req UpdateStepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := scanrun.AddStepInput{
		TenantID:          tenantID,
		TemplateID:        templateID,
		Name:              req.Name,
		Description:       req.Description,
		Order:             req.Order,
		Tool:              req.Tool,
		Capabilities:      req.Capabilities,
		Config:            req.Config,
		TimeoutSeconds:    req.TimeoutSeconds,
		DependsOn:         req.DependsOn,
		Condition:         toCondition(req.Condition),
		MaxRetries:        req.MaxRetries,
		RetryDelaySeconds: req.RetryDelaySeconds,
	}
	if req.UIPosition != nil {
		input.UIPositionX = &req.UIPosition.X
		input.UIPositionY = &req.UIPosition.Y
	}

	// Security: verify the template belongs to the tenant before mutating a
	// step under it. UpdateStep resolves the step by raw ID, so without this
	// guard a caller could modify another tenant's step (IDOR). Mirrors
	// DeleteStep below.
	if _, err := h.service.GetTemplate(r.Context(), tenantID, templateID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	step, err := h.service.UpdateStep(scanWorkflowAuditCtx(r), stepID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toStepResponse(step))
}

// DeleteStep handles DELETE /api/v1/scan-workflows/templates/{id}/steps/{stepId}
func (h *ScanWorkflowHandler) DeleteStep(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	templateID := chi.URLParam(r, "id")
	stepID := chi.URLParam(r, "stepId")

	// Security: First verify template belongs to tenant
	_, err := h.service.GetTemplate(r.Context(), tenantID, templateID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	if err := h.service.DeleteStep(scanWorkflowAuditCtx(r), tenantID, stepID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Run Handlers ---

// GetRun handles GET /api/v1/scan-workflows/runs/{id}
func (h *ScanWorkflowHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	runID := chi.URLParam(r, "id")

	// Read by the caller's tenant: another tenant's run is not found.
	run, err := h.service.GetRunWithStepsForTenant(r.Context(), tenantID, runID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if tid, perr := shared.IDFromString(tenantID); perr != nil || !h.runVisible(r.Context(), tid, run) {
		apierror.NotFound("Run").WriteJSON(w)
		return
	}

	resp := withRunTriggerLabel(toRunResponse(run), runTriggerNames(r.Context(), h.users, h.logger, run))
	tasks, err := h.service.GetRunTasks(r.Context(), run)
	if err != nil {
		h.logger.Error("failed to read run tasks", "run_id", run.ID.String(), "error", err)
		apierror.InternalServerError("failed to read the run's tasks").WriteJSON(w)
		return
	}
	if tasks != nil {
		resp.TaskSummary = toRunTaskSummaryResponse(tasks.Summary)
		resp.Tasks = toRunTaskResponses(tasks.Items)
		h.withHostWaits(r.Context(), tenantID, run.ID.String(), resp.Tasks)
		resp.TasksTruncated = tasks.Truncated
		resp.TasksNextCursor = tasks.NextCursor
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListRuns handles GET /api/v1/scan-workflows/runs
func (h *ScanWorkflowHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	page, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	input := scanrun.ListRunsInput{
		TenantID:       tenantID,
		ScanWorkflowID: r.URL.Query().Get("scan_workflow_id"),
		ScanID:         r.URL.Query().Get("scan_id"),
		Kinds:          parseQueryArray(r.URL.Query().Get("kind")),
		IncludeSystem:  r.URL.Query().Get("include_system") == queryParamTrue,
		Origin:         r.URL.Query().Get("origin"),
		AssetID:        r.URL.Query().Get("asset_id"),
		Status:         r.URL.Query().Get("status"),
		Sort:           r.URL.Query().Get("sort"),
		Page:           page.Page,
		PerPage:        page.PerPage,
	}
	if tid, perr := shared.IDFromString(tenantID); perr == nil && h.listHidesFindingRuns(r.Context(), tid) {
		input.ExcludeKinds = []string{string(scanrundom.RunKindRetest), string(scanrundom.RunKindValidation)}
	}

	result, err := h.service.ListRuns(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	summaries, err := h.service.RunTaskSummaries(r.Context(), tenantID, result.Data)
	if err != nil {
		h.logger.Error("failed to summarize run tasks", "error", err)
		apierror.InternalServerError("failed to read the runs' tasks").WriteJSON(w)
		return
	}
	scanNames, err := h.service.RunScanNames(r.Context(), tenantID, result.Data)
	if err != nil {
		h.logger.Error("failed to name run scans", "error", err)
		apierror.InternalServerError("failed to read the runs' scans").WriteJSON(w)
		return
	}
	managers, err := h.service.RunScanManagers(r.Context(), tenantID, result.Data)
	if err != nil {
		h.logger.Error("failed to read the runs' managing policies", "error", err)
		apierror.InternalServerError("failed to read the runs' scans").WriteJSON(w)
		return
	}
	names := runTriggerNames(r.Context(), h.users, h.logger, result.Data...)
	items := make([]*RunResponse, len(result.Data))
	for i, run := range result.Data {
		items[i] = withRunTriggerLabel(toRunResponse(run), names)
		if sum, ok := summaries[run.ID]; ok {
			items[i].TaskSummary = toRunTaskSummaryResponse(sum)
		}
		if run.ScanID != nil {
			items[i].ScanName = scanNames[*run.ScanID]
			items[i].ManagedBy = managers[*run.ScanID]
		}
	}

	resp := pagination.Result[*RunResponse]{
		Data:       items,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListRunTasks handles GET /api/v1/scan-runs/{id}/tasks
// @Summary      List a run's tasks
// @Description  One page of the run's tasks (one dispatched command each) in dispatch order. Page with next_cursor. Targets are counted, not listed.
// @Tags         Scan workflows
// @Produce      json
// @Param        id        path      string  true   "Run ID"
// @Param        cursor    query     string  false  "next_cursor of the previous page"
// @Param        per_page  query     int     false  "Tasks per page (1-200)" default(50)
// @Success      200  {object}  RunTaskPageResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-runs/{id}/tasks [get]
func (h *ScanWorkflowHandler) ListRunTasks(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	runID := chi.URLParam(r, "id")
	q := r.URL.Query()
	if !h.guardRun(w, r) {
		return
	}

	perPage := 0
	if raw := q.Get("per_page"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			apierror.BadRequest("per_page must be a number").WriteJSON(w)
			return
		}
		perPage = n
		if perPage == 0 {
			perPage = -1 // explicit 0 is out of range, not "default"
		}
	}

	page, err := h.service.ListRunTasksPage(r.Context(), tenantID, runID, q.Get("cursor"), perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	resp := RunTaskPageResponse{Data: toRunTaskResponses(page.Items), NextCursor: page.NextCursor}
	h.withHostWaits(r.Context(), tenantID, runID, resp.Data)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CancelRun handles POST /api/v1/scan-workflows/runs/{id}/cancel
func (h *ScanWorkflowHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	if !h.guardRun(w, r) {
		return
	}

	if err := h.service.CancelRun(scanWorkflowAuditCtx(r), tenantID, runID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Conversion Helpers ---

func toSettings(settings *ScanWorkflowSettingsRequest) *scanworkflow.Settings {
	if settings == nil {
		return nil
	}
	s := &scanworkflow.Settings{
		MaxParallelSteps: settings.MaxParallelSteps,
		FailFast:         settings.FailFast,
		TimeoutSeconds:   settings.TimeoutSeconds,
	}
	if settings.DeltaGating != nil {
		s.DeltaGating = *settings.DeltaGating
	}
	if settings.ContinueOnFailedDependency != nil {
		s.ContinueOnFailedDependency = *settings.ContinueOnFailedDependency
	}
	if settings.StageBarrier != nil {
		s.StageBarrier = *settings.StageBarrier
	}
	if settings.SensorPreference != "" {
		s.SensorPreference = scanworkflow.SensorPreference(settings.SensorPreference)
	}
	return s
}

func toCondition(cond *StepConditionRequest) *scanworkflow.Condition {
	if cond == nil {
		return nil
	}
	return &scanworkflow.Condition{
		Type:  scanworkflow.ConditionType(cond.Type),
		Value: cond.Value,
	}
}

func toUIPosition(pos *UIPositionRequest) *scanworkflow.UIPosition {
	if pos == nil {
		return nil
	}
	return &scanworkflow.UIPosition{
		X: pos.X,
		Y: pos.Y,
	}
}

func toTemplateResponse(t *scanworkflow.Workflow) *TemplateResponse {
	steps := make([]StepResponse, len(t.Steps))
	for i, s := range t.Steps {
		steps[i] = *toStepResponse(s)
	}

	resp := &TemplateResponse{
		ID:               t.ID.String(),
		TenantID:         t.TenantID.String(),
		Name:             t.Name,
		Description:      t.Description,
		Version:          t.Version,
		IsActive:         t.IsActive,
		IsSystemTemplate: t.IsSystemTemplate,
		Settings: ScanWorkflowSettingsResponse{
			MaxParallelSteps:           t.Settings.MaxParallelSteps,
			FailFast:                   t.Settings.FailFast,
			TimeoutSeconds:             t.Settings.TimeoutSeconds,
			SensorPreference:           string(t.Settings.SensorPreference),
			DeltaGating:                t.Settings.DeltaGating,
			ContinueOnFailedDependency: t.Settings.ContinueOnFailedDependency,
			StageBarrier:               t.Settings.StageBarrier,
		},
		Tags:      t.Tags,
		Steps:     steps,
		CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if t.IsRetiredSystem() {
		resp.IsRetired = true
		resp.SupersededBy = supersededRef(t)
	}

	if t.RetiredAt != nil {
		resp.RetiredAt = t.RetiredAt.Format("2006-01-02T15:04:05Z07:00")
	}

	// Add UI positions for visual builder
	if t.UIStartPosition != nil {
		resp.UIStartPosition = &UIPositionResponse{X: t.UIStartPosition.X, Y: t.UIStartPosition.Y}
	}
	if t.UIEndPosition != nil {
		resp.UIEndPosition = &UIPositionResponse{X: t.UIEndPosition.X, Y: t.UIEndPosition.Y}
	}

	return resp
}

func toStepResponse(s *scanworkflow.Step) *StepResponse {
	resp := &StepResponse{
		ID:          s.ID.String(),
		StepKey:     s.StepKey,
		Name:        s.Name,
		Description: s.Description,
		Order:       s.StepOrder,
		UIPosition: UIPositionResponse{
			X: s.UIPosition.X,
			Y: s.UIPosition.Y,
		},
		Tool:              s.Tool,
		Capabilities:      s.Capabilities,
		PreferTools:       append([]string{}, s.PreferTools...),
		ToolSelection:     string(s.Selection()),
		Config:            s.Config,
		TimeoutSeconds:    s.TimeoutSeconds,
		DependsOn:         s.DependsOn,
		MaxRetries:        s.MaxRetries,
		RetryDelaySeconds: s.RetryDelaySeconds,
	}
	if !s.RunPolicy.IsZero() {
		p := s.RunPolicy.Clone()
		resp.RunPolicy = &p
	}

	if s.Condition.Type != "" {
		resp.Condition = &StepConditionResponse{
			Type:  string(s.Condition.Type),
			Value: s.Condition.Value,
		}
	}

	return resp
}

// RunResult is the conclusion of a completed run (retest outcomes).
type RunResult struct {
	// Kind is the outcome, e.g. inconclusive or still_exposed_elsewhere.
	Kind string `json:"kind"`
	// Code is the reason code in lower case, e.g. endpoint_mismatch.
	Code string `json:"code,omitempty"`
}

// runResultOf reads a run's result from its context (written when a retest
// run completes with a conclusion); nil when it has none.
func runResultOf(ctx map[string]any) *RunResult {
	m, ok := ctx[scanrun.RunContextResult].(map[string]any)
	if !ok {
		return nil
	}
	kind, _ := m["kind"].(string)
	if kind == "" {
		return nil
	}
	code, _ := m["code"].(string)
	return &RunResult{Kind: kind, Code: code}
}

func toRunResponse(r *scanrundom.Run) *RunResponse {
	resp := &RunResponse{
		ID:             r.ID.String(),
		TenantID:       r.TenantID.String(),
		ScanWorkflowID: r.ScanWorkflowID.String(),
		Intensity:      string(scansvc.RunIntensity(r)),
		TriggerType:    string(r.TriggerType),
		TriggeredBy:    r.TriggeredBy,
		Status:         string(r.Status),
		TotalSteps:     r.TotalSteps,
		CompletedSteps: r.CompletedSteps,
		FailedSteps:    r.FailedSteps,
		SkippedSteps:   r.SkippedSteps,
		TotalFindings:  r.TotalFindings,
		ErrorMessage:   r.ErrorMessage,
		RefusalCode:    r.RefusalCode,
		Kind:           string(r.KindOrDefault()),
		Trigger:        ptrRunTrigger(runTrigger(r)),
		Subject:        r.Subject,
		Result:         runResultOf(r.Context),
		CreatedAt:      r.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),

		ScanWorkflowVersion: r.ScanWorkflowVersion,
		SpecDigest:          r.SpecDigest,
	}

	if r.AssetID != nil {
		aid := r.AssetID.String()
		resp.AssetID = &aid
	}

	if r.ScanID != nil {
		sid := r.ScanID.String()
		resp.ScanID = &sid
	}

	if r.ScanProfileID != nil {
		spid := r.ScanProfileID.String()
		resp.ScanProfileID = &spid
	}

	if r.ScheduledFor != nil {
		sf := r.ScheduledFor.Format("2006-01-02T15:04:05Z07:00")
		resp.ScheduledFor = &sf
	}
	if r.DeadlineAt != nil {
		d := r.DeadlineAt.Format("2006-01-02T15:04:05Z07:00")
		resp.DeadlineAt = &d
		resp.DeadlineReason = r.DeadlineReason
	}
	resp.UnfinishedTargetCount = r.UnfinishedTargetCount

	if r.QualityGateResult != nil {
		resp.QualityGateResult = r.QualityGateResult
	}

	if r.StartedAt != nil {
		ts := r.StartedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.StartedAt = &ts
	}

	if r.CompletedAt != nil {
		ts := r.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &ts
	}

	if len(r.StepRuns) > 0 {
		resp.StepRuns = make([]StepRunResponse, len(r.StepRuns))
		for i, sr := range r.StepRuns {
			resp.StepRuns[i] = toStepRunResponse(sr)
		}
	}

	resp.UnreachableTargetCount = contextCount(r.Context, scanrun.RunContextKeyUnreachableCount)
	resp.SkippedTargetCount = contextCount(r.Context, scanrun.RunContextKeySkippedCount)
	resp.NoLongerResolveCount = contextCount(r.Context, scanrun.RunContextKeyNoLongerResolve)

	// Extract filtering result from context if present
	if r.Context != nil {
		if filteringResult, ok := r.Context["filtering_result"]; ok {
			resp.FilteringResult = toFilteringResultResponse(filteringResult)
		}
		resp.Dispatch = toRunDispatchResponse(r.Context)
		resp.WindowWaits = toRunWindowWaits(r.Context)
		// Names the sensors found no longer resolve: an informational skip
		// group (a fact about the names, never a failure), next to the
		// dispatch groups.
		if n := resp.NoLongerResolveCount; n > 0 {
			if resp.Dispatch == nil {
				resp.Dispatch = &RunDispatchResponse{}
			}
			resp.Dispatch.Skipped = append(resp.Dispatch.Skipped, scansvc.SkipGroup{
				Reason: scanrundom.SkipReasonTargetUnresolvable, Tone: scansvc.SkipToneInfo, Count: n, Targets: []string{},
			})
		}
	}

	return resp
}

// toRunDispatchResponse reads the dispatch report the scan trigger stores in
// the run context. Values round-trip through JSON so the same code reads a
// freshly built context and one loaded from the database.
func toRunDispatchResponse(runContext map[string]any) *RunDispatchResponse {
	keys := []string{"resolved_target_count", "excluded_target_count", "excluded_targets", "dispatch_warnings", "uncovered_targets", "zone_routing", "sensor_routing", "target_expansion", scansvc.RunContextKeySkipped}
	present := map[string]any{}
	for _, k := range keys {
		if v, ok := runContext[k]; ok && v != nil {
			present[k] = v
		}
	}
	if len(present) == 0 {
		return nil
	}
	raw, err := json.Marshal(present)
	if err != nil {
		return nil
	}
	var in struct {
		Resolved  int                  `json:"resolved_target_count"`
		Excluded  int                  `json:"excluded_target_count"`
		Detail    []RunExcludedTarget  `json:"excluded_targets"`
		Warnings  []string             `json:"dispatch_warnings"`
		Uncovered []RunUncoveredTarget `json:"uncovered_targets"`
		Routing   *RunZoneRouting      `json:"zone_routing"`
		Sensor    string               `json:"sensor_routing"`
		Expansion []RunTargetExpansion `json:"target_expansion"`
		Skipped   []scansvc.SkipGroup  `json:"skipped_targets"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil
	}
	out := &RunDispatchResponse{
		ResolvedTargets:  in.Resolved,
		ExcludedTargets:  in.Excluded,
		Excluded:         in.Detail,
		Warnings:         in.Warnings,
		UncoveredTargets: in.Uncovered,
		ZoneRouting:      in.Routing,
		SensorRouting:    in.Sensor,
		TargetExpansion:  in.Expansion,
	}
	if _, recorded := present[scansvc.RunContextKeySkipped]; recorded {
		will := in.Resolved
		if in.Routing != nil {
			will -= in.Routing.UncoveredTargets
		}
		out.WillScan, out.Skipped = &will, in.Skipped
	}
	return out
}

// toFilteringResultResponse converts filtering result from context to response type.
func toFilteringResultResponse(result any) *FilteringResultResponse {
	if result == nil {
		return nil
	}

	// Type assertion - FilteringResult may come from scan package
	// We handle both map[string]any (from JSON) and direct struct
	switch v := result.(type) {
	case map[string]any:
		resp := &FilteringResultResponse{}
		if total, ok := v["total_assets"].(int); ok {
			resp.TotalAssets = total
		}
		if scanned, ok := v["scanned_assets"].(int); ok {
			resp.ScannedAssets = scanned
		}
		if skipped, ok := v["skipped_assets"].(int); ok {
			resp.SkippedAssets = skipped
		}
		if unclassified, ok := v["unclassified_assets"].(int); ok {
			resp.UnclassifiedAssets = unclassified
		}
		if pct, ok := v["compatibility_percent"].(float64); ok {
			resp.CompatibilityPercent = pct
		}
		if filtered, ok := v["was_filtered"].(bool); ok {
			resp.WasFiltered = filtered
		}
		if toolName, ok := v["tool_name"].(string); ok {
			resp.ToolName = toolName
		}
		if targets, ok := v["supported_targets"].([]string); ok {
			resp.SupportedTargets = targets
		}
		if scannedByType, ok := v["scanned_by_type"].(map[string]int); ok {
			resp.ScannedByType = scannedByType
		}
		if skippedByType, ok := v["skipped_by_type"].(map[string]int); ok {
			resp.SkippedByType = skippedByType
		}
		return resp

	default:
		// Try to access fields directly if it's a struct with exported fields
		// This handles the case where FilteringResult struct is passed directly
		return toFilteringResultFromStruct(v)
	}
}

// toFilteringResultFromStruct converts a struct to FilteringResultResponse.
func toFilteringResultFromStruct(v any) *FilteringResultResponse {
	if v == nil {
		return nil
	}

	// Handle the actual FilteringResult type from scan service
	if fr, ok := v.(*scansvc.FilteringResult); ok && fr != nil {
		resp := &FilteringResultResponse{
			TotalAssets:          fr.TotalAssets,
			ScannedAssets:        fr.ScannedAssets,
			SkippedAssets:        fr.SkippedAssets,
			UnclassifiedAssets:   fr.UnclassifiedAssets,
			CompatibilityPercent: fr.CompatibilityPercent,
			ScannedByType:        fr.ScannedByType,
			SkippedByType:        fr.SkippedByType,
			WasFiltered:          fr.WasFiltered,
			ToolName:             fr.ToolName,
			SupportedTargets:     fr.SupportedTargets,
		}

		// Convert skip reasons
		if len(fr.SkipReasons) > 0 {
			resp.SkipReasons = make([]SkipReasonResponse, len(fr.SkipReasons))
			for i, sr := range fr.SkipReasons {
				resp.SkipReasons[i] = SkipReasonResponse{
					AssetType: sr.AssetType,
					Count:     sr.Count,
					Reason:    sr.Reason,
				}
			}
		}

		return resp
	}

	// Return nil for unhandled types
	return nil
}

func toStepRunResponse(sr *scanrundom.StepRun) StepRunResponse {
	resp := StepRunResponse{
		ID:            sr.ID.String(),
		StepKey:       sr.StepKey,
		StepName:      sr.StepName,
		Tool:          sr.Tool,
		Capability:    sr.Capability,
		Status:        string(sr.Status),
		ErrorMessage:  sr.ErrorMessage,
		ErrorCode:     sr.ErrorCode,
		ErrorClass:    stepErrorClass(sr.ErrorCode),
		Attempt:       sr.Attempt,
		MaxAttempts:   sr.MaxAttempts,
		FindingsCount: sr.FindingsCount,
	}
	if !sr.StepID.IsZero() {
		resp.StepID = sr.StepID.String()
	}

	if sr.StartedAt != nil {
		ts := sr.StartedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.StartedAt = &ts
	}

	if sr.CompletedAt != nil {
		ts := sr.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &ts
	}

	return resp
}

// handleValidationError converts validation errors to API errors.
func (h *ScanWorkflowHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

// handleServiceError converts service errors to API errors.
func (h *ScanWorkflowHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case writeGraphInvalid(w, err):
	case errors.Is(err, scanworkflow.ErrScanWorkflowRunActive):
		apierror.New(http.StatusConflict, apierror.Code(scanworkflow.ErrScanWorkflowRunActive.Code), scanworkflow.ErrScanWorkflowRunActive.Message).WriteJSON(w)
	case errors.Is(err, scanworkflow.ErrScanWorkflowRetired):
		apierror.New(http.StatusConflict, apierror.Code(scanworkflow.ErrScanWorkflowRetired.Code), scanworkflow.ErrScanWorkflowRetired.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scan workflow").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("A scan workflow with this name already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
	}
}

// handleStepError converts step-related service errors to API errors.
func (h *ScanWorkflowHandler) handleStepError(w http.ResponseWriter, err error) {
	switch {
	case writeGraphInvalid(w, err):
	case errors.Is(err, scanworkflow.ErrScanWorkflowRunActive):
		apierror.New(http.StatusConflict, apierror.Code(scanworkflow.ErrScanWorkflowRunActive.Code), scanworkflow.ErrScanWorkflowRunActive.Message).WriteJSON(w)
	case errors.Is(err, scanworkflow.ErrScanWorkflowRetired):
		apierror.New(http.StatusConflict, apierror.Code(scanworkflow.ErrScanWorkflowRetired.Code), scanworkflow.ErrScanWorkflowRetired.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Step").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Another step of this scan workflow already uses this key").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("step service error", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
	}
}

// scanWorkflowAuditCtx is the request context carrying the caller as the scan workflow
// service's audit actor (see scanrun.WithAuditActor).
func scanWorkflowAuditCtx(r *http.Request) context.Context {
	return scanrun.WithAuditActor(r.Context(), middleware.GetUserID(r.Context()))
}

// stepErrorClass is the failure class of a step's error code, or "" for a
// step without one.
func stepErrorClass(code string) string {
	if code == "" {
		return ""
	}
	return string(scanrundom.ClassOf(code))
}

// SetUserNames lets run responses name the people who started them.
func (h *ScanWorkflowHandler) SetUserNames(users user.Repository) { h.users = users }

func ptrRunTrigger(t RunTrigger) *RunTrigger { return &t }

// contextCount reads a count a run recorded in its context: an int in
// memory, a float64 after the JSON round trip.
func contextCount(runContext map[string]any, key string) int {
	switch n := runContext[key].(type) {
	case int:
		return max(n, 0)
	case float64:
		return max(int(n), 0)
	}
	return 0
}
