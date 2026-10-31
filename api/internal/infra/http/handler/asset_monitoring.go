package handler

// The derived monitoring state on asset list rows
// (docs/architecture/exposure-taxonomy.md, "Monitoring state"): one label
// per asset over the attribution, the scope exclusions and their kind, the
// scope status and the asset's status, read for the page only (with
// ?with_triage=true) in the caller's tenant. A failed read leaves the field
// out (the list is still served) and is logged.

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetMonitoringReader reads the derived monitoring state of a page of the
// tenant's assets (*postgres.AssetRepository).
type AssetMonitoringReader interface {
	MonitoringStates(ctx context.Context, tenantID shared.ID, ids []string, unclassifiedScanned bool) (map[string]string, error)
}

// AssetUnclassifiedPolicy is the tenant's unclassified-scans mode as the
// active-scan gate applies it (*easm.ActiveGate).
type AssetUnclassifiedPolicy interface {
	UnclassifiedMode(ctx context.Context, tenantID shared.ID) (string, error)
}

// SetMonitoring wires the monitoring state. Without a reader rows carry no
// state; without a policy unclassified assets count as not scanned.
func (h *AssetHandler) SetMonitoring(policy AssetUnclassifiedPolicy, reader AssetMonitoringReader) {
	h.unclassifiedPolicy, h.monitoringReader = policy, reader
}

// unclassifiedScanned reports whether the tenant scans assets no scope entry
// covers. Unknown is false: such assets are then labeled not monitored,
// never monitored.
func (h *AssetHandler) unclassifiedScanned(r *http.Request, tenantID string) bool {
	if h.unclassifiedPolicy == nil {
		return false
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return false
	}
	mode, err := h.unclassifiedPolicy.UnclassifiedMode(r.Context(), tid)
	return err == nil && mode != "" && mode != "off"
}

func (h *AssetHandler) addMonitoringStates(r *http.Request, tenantID string, out []*AssetResponse) {
	if h.monitoringReader == nil || len(out) == 0 || r.URL.Query().Get("with_triage") != "true" {
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
	states, err := h.monitoringReader.MonitoringStates(r.Context(), tid, ids, h.unclassifiedScanned(r, tenantID))
	if err != nil {
		h.logger.Warn("asset monitoring state not read", "error", logger.SanitizeError(err))
		return
	}
	for _, a := range out {
		a.MonitoringState = states[a.ID]
	}
}
