package handler

// Triage fields on asset list rows (research/124, RFC-054 §15): the asset's
// attribution and what an active scan would do with it now, from the same
// active-scan gate the dispatcher uses, so a row's "not in scope: passive
// only" badge never disagrees with a scan. Asked for with
// ?with_triage=true; read for the page only (at most the page size), in the
// caller's tenant. A failed read leaves the fields out (the list is still
// served) and is logged: the UI then shows the state as unknown, never as
// scannable.

import (
	"context"
	"net/http"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
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
	// refusal code (RFC-054 §6.5).
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

// SetTriage wires the triage fields. Without it ?with_triage is ignored.
func (h *AssetHandler) SetTriage(g AssetTriageGate, r AssetTriageRecords) {
	h.triageGate, h.triageRecords = g, r
}

func (h *AssetHandler) addTriage(r *http.Request, tenantID string, out []*AssetResponse) {
	if h.triageGate == nil || h.triageRecords == nil || len(out) == 0 || r.URL.Query().Get("with_triage") != "true" {
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
	for _, a := range out {
		t := &AssetTriage{AttributionState: string(attribution.StateConfirmed), Confidence: 100, ScanAllowed: true}
		if rec, ok := recs[a.ID]; ok {
			t.AttributionState, t.Confidence, t.HumanDecided = string(rec.State), rec.Confidence, rec.HumanDecided
		}
		if st, no := blocked[a.ID]; no {
			t.ScanAllowed = false
			t.ScanBlockedBy = string(st)
			t.ScanRefusalCode = scansvc.RefusalCodeForState(st)
		}
		a.Triage = t
	}
}
