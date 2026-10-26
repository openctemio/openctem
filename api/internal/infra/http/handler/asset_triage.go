package handler

// Triage fields on asset list rows (research/124, RFC-054 §15): the asset's
// attribution and what an active scan would do with it now, from the same
// checks the dispatcher runs (the active-scan gate, then the scope
// exclusions), so a row's "not in scope: passive only" badge never
// disagrees with a scan. Asked for with
// ?with_triage=true; read for the page only (at most the page size), in the
// caller's tenant. A failed read leaves the fields out (the list is still
// served) and is logged: the UI then shows the state as unknown, never as
// scannable.

import (
	"context"
	"net/http"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetTriage is what triage needs per row.
type AssetTriage struct {
	// AttributionState: confirmed (also for an asset with no record),
	// discovered, needs_review, candidate, dependency, monitor_only or
	// rejected.
	AttributionState string `json:"attribution_state"`
	// Confidence is the attribution confidence, 0-100 (100 without a record).
	Confidence   int  `json:"confidence"`
	HumanDecided bool `json:"human_decided"`
	// ScanAllowed: an active scan may reach the asset now.
	ScanAllowed bool `json:"scan_allowed"`
	// ScanBlockedBy is the gate's answer when it may not (discovered,
	// unattributed, out_of_scope, rejected, ...), ScanRefusalCode its
	// refusal code.
	ScanBlockedBy   string `json:"scan_blocked_by,omitempty"`
	ScanRefusalCode string `json:"scan_refusal_code,omitempty"`
}

// AssetTriageGate is the active-scan gate (*easm.ActiveGate).
type AssetTriageGate interface {
	ActiveCheckBlocked(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.State, error)
}

// AssetTriageRecords reads attribution records (*postgres.AttributionRepository).
type AssetTriageRecords interface {
	Records(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.Record, error)
}

// AssetTriageExclusions reports which assets an active scope exclusion
// matches, failing closed (*scope.Service).
type AssetTriageExclusions interface {
	ExcludedTargets(ctx context.Context, tenantID string, candidates []scopeapp.ExclusionCandidate) (map[shared.ID]bool, error)
}

// SetTriage wires the triage fields. Without it ?with_triage is ignored.
func (h *AssetHandler) SetTriage(g AssetTriageGate, r AssetTriageRecords, x AssetTriageExclusions) {
	h.triageGate, h.triageRecords, h.triageExclusions = g, r, x
}

func (h *AssetHandler) addTriage(r *http.Request, tenantID string, out []*AssetResponse, assets []*asset.Asset) {
	if h.triageGate == nil || h.triageRecords == nil || h.triageExclusions == nil || len(out) == 0 ||
		r.URL.Query().Get("with_triage") != "true" {
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	ids := make([]string, 0, len(out))
	for _, a := range out {
		ids = append(ids, a.ID)
	}
	ctx := r.Context()
	recs, err := h.triageRecords.Records(ctx, tid, ids)
	if err != nil {
		h.logger.Warn("asset triage: attribution not read", "error", logger.SanitizeError(err))
		return
	}
	blocked, err := h.triageGate.ActiveCheckBlocked(ctx, tid, ids)
	if err != nil {
		h.logger.Warn("asset triage: active-scan gate not read", "error", logger.SanitizeError(err))
		return
	}
	cands := make([]scopeapp.ExclusionCandidate, 0, len(assets))
	for _, a := range assets {
		cands = append(cands, scopeapp.ExclusionCandidate{ID: a.ID(),
			Values: scopeapp.AssetExclusionValues(a.Type().String(), a.Name(), a.Properties())})
	}
	excluded, err := h.triageExclusions.ExcludedTargets(ctx, tenantID, cands)
	if err != nil {
		h.logger.Warn("asset triage: exclusions not read", "error", logger.SanitizeError(err))
		return
	}
	for _, a := range out {
		t := &AssetTriage{AttributionState: string(attribution.StateConfirmed), Confidence: 100, ScanAllowed: true}
		if rec, ok := recs[a.ID]; ok {
			t.AttributionState, t.Confidence, t.HumanDecided = string(rec.State), rec.Confidence, rec.HumanDecided
		}
		if st, no := blocked[a.ID]; no {
			t.ScanAllowed = false
			t.ScanBlockedBy = string(st)
			t.ScanRefusalCode = scansvc.RefusalCodeForState(st)
		} else if id, err := shared.IDFromString(a.ID); err == nil && excluded[id] {
			// The dispatcher drops an excluded target after the gate.
			t.ScanAllowed = false
			t.ScanBlockedBy = scopedom.RefusalExcluded
			t.ScanRefusalCode = scopedom.RefusalExcluded
		}
		a.Triage = t
	}
}
