// Package validation defines the Stage-4 contract: WHAT gets validated,
// WHAT counts as evidence, WHO gates it — but NOT HOW a technique
// runs.
//
// Q2/WS-D, architectural note: OpenCTEM is agent-based. The API is an
// ORCHESTRATOR, not an executor. Actual exploit execution, cloud
// probes, and adversary emulation run on the agent that lives in the
// tenant's network, has tenant-local credentials, and can legally
// reach the target.
//
// This package therefore holds:
//   - Data shapes (TechniqueID, Target, Evidence, Outcome)
//   - The attacker-profile gate (API-side policy)
//   - The Dispatcher contract (API submits a job → agent executes →
//     agent posts Evidence back via the ingest API)
//   - EvidenceStore + Redactor (API persists, redacts secrets)
//
// What this package does NOT hold:
//   - Any direct call to AWS / Atomic Red Team / Caldera / Nuclei.
//     Those belong to the agent repo.
package validation

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TechniqueID is the MITRE ATT&CK technique identifier. The API does
// not interpret it — it is passed to the agent unchanged.
type TechniqueID string

// Target identifies what we are validating against. The executor kind
// determines which fields it uses.
type Target struct {
	AssetID  shared.ID
	Type     string // "host" | "web_url" | "api_endpoint" | "cloud_resource"
	Address  string // host:port, URL, ARN, etc.
	Metadata map[string]any
}

// Evidence is everything a reviewer needs to judge whether the
// technique was executed and what it produced. Produced by the agent
// and POSTed back through the validation-ingest endpoint.
type Evidence struct {
	// ExecutorKind identifies which agent-side tool produced this
	// evidence. Enforced by the ingest handler against the
	// ExecutorKind declared on the job.
	ExecutorKind string
	Technique    TechniqueID
	Target       Target
	StartedAt    time.Time
	EndedAt      time.Time
	Outcome      Outcome
	Summary      string
	Artifacts    []string // attachment IDs (screenshots, PCAPs)
	RawMeta      map[string]any
}

// Executor is a back-compat accessor for legacy handler code that
// already referenced the field. Prefer ExecutorKind directly.
//
// Deprecated: read ExecutorKind.
func (e Evidence) Executor() string { return e.ExecutorKind }

// Outcome is the exit status of an execution.
type Outcome string

const (
	OutcomeDetected    Outcome = "detected"
	OutcomeNotDetected Outcome = "not_detected"
	OutcomeInconclusive Outcome = "inconclusive"
	OutcomeError       Outcome = "error"
	OutcomeSkipped     Outcome = "skipped"
)

// ExecutorKind enumerates the validation tool the AGENT will run.
// The API uses this string to route jobs to agents that declare they
// support it. The API does not import or call the tool itself.
type ExecutorKind string

const (
	KindSafeCheck     ExecutorKind = "safe-check"
	KindAtomicRedTeam ExecutorKind = "atomic-red-team"
	KindCaldera       ExecutorKind = "caldera"
	KindNuclei        ExecutorKind = "nuclei"
)

// AttackerProfile is the narrow subset of the full profile that the
// API-side selection / gating logic needs. It never travels to the
// agent — the agent receives the already-approved executor kind and
// technique.
type AttackerProfile struct {
	ID           shared.ID
	Name         string
	Capabilities []string // "external-unauth" | "credentialed" | "network-pivot" | ...
}

// ValidationJob is the payload the API queues for an agent. Agents
// long-poll for jobs that match their advertised ExecutorKinds.
// Result is delivered via POST /api/v1/validation/evidence.
type ValidationJob struct {
	JobID          shared.ID
	TenantID       shared.ID
	FindingID      shared.ID
	ExecutorKind   ExecutorKind
	Technique      TechniqueID
	Target         Target
	ProfileID      shared.ID
	TimeoutSeconds int
}

// ValidationDispatcher submits a job for an agent and returns the
// resulting Evidence when the agent has reported back. Concrete
// implementations plug into the platform-job queue (Redis / Postgres).
//
// Submit is expected to BLOCK until the agent finishes OR the context
// deadline fires — callers choose the deadline. In practice the
// implementation is queue + subscribe, not a synchronous call.
type ValidationDispatcher interface {
	Submit(ctx context.Context, job ValidationJob) (Evidence, error)
}

// Selector owns the API-side policy: given a technique + attacker
// profile + a list of executor kinds the agent fleet supports, pick
// the appropriate kind.
type Selector interface {
	Select(tid TechniqueID, profile *AttackerProfile, available []ExecutorKind) (ExecutorKind, error)
}

// DefaultSelector applies a conservative mapping:
//   - safe-check is preferred when available — cheapest + legally safest
//   - nuclei is next for web-reachable targets
//   - atomic-red-team / caldera require a non-empty profile capability
//     set (waiver + adversary emulation opt-in)
type DefaultSelector struct{}

// Select picks the first available executor that fits the policy.
func (DefaultSelector) Select(
	tid TechniqueID,
	profile *AttackerProfile,
	available []ExecutorKind,
) (ExecutorKind, error) {
	preferred := []ExecutorKind{KindSafeCheck, KindNuclei, KindAtomicRedTeam, KindCaldera}
	set := make(map[ExecutorKind]bool, len(available))
	for _, k := range available {
		set[k] = true
	}
	for _, k := range preferred {
		if !set[k] {
			continue
		}
		if !kindAllowedByProfile(k, profile) {
			continue
		}
		if !kindSupportsTechnique(k, tid) {
			continue
		}
		return k, nil
	}
	return "", ErrNoExecutor
}

// kindAllowedByProfile enforces the attacker-profile gate. Policy
// lives on the API side — the agent never decides whether to run.
func kindAllowedByProfile(k ExecutorKind, profile *AttackerProfile) bool {
	switch k {
	case KindSafeCheck, KindNuclei:
		return true
	case KindAtomicRedTeam, KindCaldera:
		if profile == nil || len(profile.Capabilities) == 0 {
			return false
		}
		return true
	}
	return false
}

// kindSupportsTechnique is a rough technique compatibility check.
// The ground truth lives at the agent (which templates/atomics are
// installed), but we short-circuit the obvious mismatches here.
func kindSupportsTechnique(k ExecutorKind, tid TechniqueID) bool {
	if tid == "" {
		return false
	}
	switch k {
	case KindSafeCheck:
		switch tid {
		case "T1046", "T1590", "T1595":
			return true
		}
		return false
	case KindNuclei, KindAtomicRedTeam, KindCaldera:
		return true
	}
	return false
}

// ErrNoExecutor is returned by Selector.Select when nothing in the
// available list matches the policy.
var ErrNoExecutor = errors.New("no executor available")
