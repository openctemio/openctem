package asset

// Governance of edits that lower an asset's risk inputs
// (docs/architecture/asset-risk-governance.md): exposure, criticality and the
// crown-jewel flag feed every finding's priority class. Raising them is free;
// lowering them changes how the findings on the asset are classified, so an
// edit that would lower an open P0/P1 finding is decided under the
// organization's approval policy.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PriorityInputs are the asset attributes the priority classifier reads that a
// person can lower.
type PriorityInputs struct {
	Exposure    Exposure
	Criticality Criticality
	CrownJewel  bool
}

// PriorityInputsOf reads the inputs of an asset.
func PriorityInputsOf(a *Asset) PriorityInputs {
	return PriorityInputs{Exposure: a.Exposure(), Criticality: a.Criticality(), CrownJewel: a.IsCrownJewel()}
}

// exposureRank orders exposure by how reachable the asset is: public is the
// most, isolated the least. An unknown exposure is treated as restricted (the
// default scoring rates it close to it), so moving between them is not a
// lowering, and moving from either to private or isolated is.
func exposureRank(e Exposure) int {
	switch e {
	case ExposurePublic:
		return 4
	case ExposureRestricted, ExposureUnknown, "":
		return 3
	case ExposurePrivate:
		return 2
	case ExposureIsolated:
		return 1
	}
	return 3
}

// LoweredFields names the inputs that after sets lower than before (a subset
// of exposure, criticality, crown_jewel; empty when nothing is lowered).
func LoweredFields(before, after PriorityInputs) []string {
	var out []string
	if exposureRank(after.Exposure) < exposureRank(before.Exposure) {
		out = append(out, "exposure")
	}
	if criticalityRank(after.Criticality) < criticalityRank(before.Criticality) {
		out = append(out, "criticality")
	}
	if before.CrownJewel && !after.CrownJewel {
		out = append(out, "crown_jewel")
	}
	return out
}

// RiskRequestStatus is the state of a risk change request.
type RiskRequestStatus string

// Request states.
const (
	RiskRequestPending  RiskRequestStatus = "pending"
	RiskRequestApproved RiskRequestStatus = "approved"
	RiskRequestRejected RiskRequestStatus = "rejected"
	RiskRequestCanceled RiskRequestStatus = "canceled"
	RiskRequestExpired  RiskRequestStatus = "expired"
)

// DefaultRiskDecisionWindow is how long a request waits when the policy
// names no window.
const DefaultRiskDecisionWindow = 7 * 24 * time.Hour

// RiskChangeRequest is an edit that lowers risk inputs and waits for the
// approval the organization's policy asks for. The previous values are what
// the asset had when the request was made; the request applies only while it
// still has them.
type RiskChangeRequest struct {
	ID       shared.ID
	TenantID shared.ID
	AssetID  shared.ID
	// Requested is what the person asked for; only the lowered fields differ
	// from Previous.
	Requested PriorityInputs
	Previous  PriorityInputs
	// Lowered names the fields the request lowers.
	Lowered            []string
	Reason             string
	RequestedBy        *shared.ID
	Status             RiskRequestStatus
	Tier               string
	RequiredApprovals  int
	ApprovalsCollected int
	// Impact is the preview the request was made with (JSON, kept as evidence).
	Impact       []byte
	DecideBy     time.Time
	DecidedBy    *shared.ID
	DecidedAt    *time.Time
	DecisionNote string
	CreatedAt    time.Time
}

// IsDecidable reports whether the request can still be decided at now.
func (r *RiskChangeRequest) IsDecidable(now time.Time) bool {
	return r.Status == RiskRequestPending && now.Before(r.DecideBy)
}

// Request errors.
var (
	// ErrRiskRequestPending: the asset already has a pending request.
	ErrRiskRequestPending = fmt.Errorf("%w: this asset already has a risk change waiting for approval", shared.ErrConflict)
	// ErrRiskRequestStale: the asset's inputs changed since the request was made.
	ErrRiskRequestStale = fmt.Errorf("%w: the asset changed since this request was made; request again", shared.ErrConflict)
	// ErrRiskRequestOverdue: nobody decided the request in time.
	ErrRiskRequestOverdue = fmt.Errorf("%w: this request was not decided in time and has expired", shared.ErrConflict)
	// ErrRiskSelfApproval: a requester never decides their own request.
	ErrRiskSelfApproval = fmt.Errorf("%w: you cannot approve your own request", shared.ErrForbidden)
)

// RiskSignoff is one approval given to a request.
type RiskSignoff struct {
	UserID       shared.ID
	SecurityPool bool
	PoolFallback bool
	StepUp       bool
}

// RiskChangeRequestRepository stores risk change requests; every method is
// scoped by tenant.
type RiskChangeRequestRepository interface {
	// Create stores a pending request; an asset has at most one
	// (ErrRiskRequestPending otherwise). A pending request past its decide-by
	// time is expired first.
	Create(ctx context.Context, r *RiskChangeRequest) error
	// Get returns one request of the tenant (ErrNotFound otherwise).
	Get(ctx context.Context, tenantID, id shared.ID) (*RiskChangeRequest, error)
	// Pending returns the asset's pending request that can still be decided,
	// or nil.
	Pending(ctx context.Context, tenantID, assetID shared.ID) (*RiskChangeRequest, error)
	// Signoffs lists the approvals given to a request.
	Signoffs(ctx context.Context, tenantID, id shared.ID) ([]approvalpolicy.Signoff, error)
	// SignOff records one approval with the request locked. decide judges it
	// against the approvals already given and answers whether it completes
	// the request; when it does, apply runs in the same transaction after the
	// request row is approved, and an error from it rolls everything back.
	SignOff(ctx context.Context, tenantID, id shared.ID, s RiskSignoff,
		decide func(prior []approvalpolicy.Signoff) (bool, error),
		apply func(ctx context.Context) error) (applied bool, err error)
	// Close ends a pending request as rejected or canceled. requester, when
	// set, restricts it to that person's own request.
	Close(ctx context.Context, tenantID, id shared.ID, status RiskRequestStatus, actor shared.ID, note string, requester *shared.ID) error
}

// RiskClassMove counts the open findings of an asset that would move from one
// priority class to another.
type RiskClassMove struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Count int    `json:"count"`
}

// RiskImpact is what a proposed change of an asset's priority inputs would do
// to the priority class of its open findings (a manual class override stands
// and is not counted as moved).
type RiskImpact struct {
	// Lowered names the inputs the change lowers; empty when it lowers none
	// (raising risk needs no preview).
	Lowered      []string `json:"lowered_fields"`
	OpenFindings int      `json:"open_findings"`
	// ClassDrops counts the findings whose class would drop (P1 -> P2, ...);
	// P0P1Drops those among them that are P0 or P1 today.
	ClassDrops int             `json:"class_drops"`
	P0P1Drops  int             `json:"p0_p1_drops"`
	Raised     int             `json:"raised"`
	Moves      []RiskClassMove `json:"moves"`
	// ManualOverridesKept counts findings whose class a person set; they do
	// not move.
	ManualOverridesKept int `json:"manual_overrides_kept"`
	// WorstFindingID is the P0/P1 finding the approval policy is evaluated on.
	WorstFindingID string `json:"worst_finding_id,omitempty"`
}

// RiskApprovalView says how the change would be decided for the caller now.
type RiskApprovalView struct {
	// Required: the change would wait for a second person.
	Required bool `json:"required"`
	// Tier is the policy tier (single, peer, security, dual).
	Tier              string   `json:"tier"`
	RequiredApprovals int      `json:"required_approvals"`
	Reasons           []string `json:"reasons"`
	EligibleApprovers int      `json:"eligible_approvers"`
	// Satisfiable: enough eligible people exist to approve it.
	Satisfiable   bool `json:"satisfiable"`
	MinNoteLength int  `json:"min_note_length"`
	StepUp        bool `json:"step_up"`
}

// RiskPreview is the answer of the preview endpoint.
type RiskPreview struct {
	Impact RiskImpact `json:"impact"`
	// Approval is set when the change would drop an open P0/P1 finding.
	Approval *RiskApprovalView `json:"approval,omitempty"`
	// PendingRequest is true when the asset already has a request waiting.
	PendingRequest bool `json:"pending_request"`
}
