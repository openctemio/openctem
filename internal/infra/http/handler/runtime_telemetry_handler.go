package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// RuntimeTelemetryHandler receives EDR/XDR-style runtime events from
// agents running on endpoint assets (see migration 000155).
//
// Authentication reuses the agent API-key chain already wired on the
// ingest routes (AgentFromContext). Telemetry is tenant-scoped via the
// agent's tenant_id — handler does NOT accept a tenant override from
// the body so a compromised agent cannot write into another tenant.
type RuntimeTelemetryHandler struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewRuntimeTelemetryHandler creates the handler.
func NewRuntimeTelemetryHandler(db *sql.DB, log *logger.Logger) *RuntimeTelemetryHandler {
	return &RuntimeTelemetryHandler{
		db:     db,
		logger: log.With("handler", "runtime_telemetry"),
	}
}

// runtimeEventIn is the wire format an agent emits. Keep fields
// aligned with the DB schema — the constraint lists live in the
// migration, not in Go, so new event types land as a migration-only
// change.
type runtimeEventIn struct {
	EndpointAssetID string                 `json:"endpoint_asset_id,omitempty"` // may be empty during onboarding
	EventType       string                 `json:"event_type"`                   // required, see migration CHECK
	Severity        string                 `json:"severity,omitempty"`           // info|low|medium|high|critical, default info
	ObservedAt      time.Time              `json:"observed_at"`                  // when the event happened on the endpoint
	Properties      map[string]any         `json:"properties,omitempty"`
}

// ingestRequest supports both single-event and batched submissions. A
// single POST with up to 100 events keeps network chatter low while
// agent queues are draining after a disconnect.
type ingestRequest struct {
	Events []runtimeEventIn `json:"events"`
}

type ingestResponse struct {
	Accepted int      `json:"accepted"`
	Rejected int      `json:"rejected"`
	Errors   []string `json:"errors,omitempty"`
}

// Ingest handles POST /api/v1/telemetry-events.
//
// The body is always a batch (array wrapped in {"events": [...]}) so
// the contract does not branch between single/multi. Size cap is 100
// events per request — agents that need more must paginate.
func (h *RuntimeTelemetryHandler) Ingest(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("agent authentication required").WriteJSON(w)
		return
	}

	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid JSON body").WriteJSON(w)
		return
	}
	if len(req.Events) == 0 {
		apierror.BadRequest("events array must not be empty").WriteJSON(w)
		return
	}
	if len(req.Events) > 100 {
		apierror.BadRequest("max 100 events per request").WriteJSON(w)
		return
	}

	resp := ingestResponse{}
	// Per-event insert. Batching into a single multi-VALUES INSERT is
	// the obvious optimisation once ingest rate demands it; the per-row
	// variant keeps the error message list precise for now.
	const q = `
		INSERT INTO runtime_telemetry_events
		       (tenant_id, agent_id, endpoint_asset_id, event_type, severity, observed_at, properties)
		VALUES ($1, $2, NULLIF($3,'')::uuid, $4, COALESCE(NULLIF($5,''),'info'), $6, $7)
	`
	for i, ev := range req.Events {
		if ev.EventType == "" {
			resp.Rejected++
			resp.Errors = append(resp.Errors, eventErr(i, "event_type required"))
			continue
		}
		if ev.ObservedAt.IsZero() {
			resp.Rejected++
			resp.Errors = append(resp.Errors, eventErr(i, "observed_at required"))
			continue
		}
		propsJSON, err := json.Marshal(nilMapToEmpty(ev.Properties))
		if err != nil {
			resp.Rejected++
			resp.Errors = append(resp.Errors, eventErr(i, "properties not serialisable"))
			continue
		}
		_, err = h.db.ExecContext(r.Context(), q,
			agt.TenantID.String(),
			agt.ID.String(),
			ev.EndpointAssetID,
			ev.EventType,
			ev.Severity,
			ev.ObservedAt.UTC(),
			propsJSON,
		)
		if err != nil {
			h.logger.Warn("runtime telemetry insert failed",
				"tenant_id", agt.TenantID.String(),
				"agent_id", agt.ID.String(),
				"event_type", ev.EventType,
				"error", err,
			)
			resp.Rejected++
			resp.Errors = append(resp.Errors, eventErr(i, "database insert failed"))
			continue
		}
		resp.Accepted++
	}

	w.Header().Set("Content-Type", "application/json")
	if resp.Accepted == 0 && resp.Rejected > 0 {
		// Whole batch was bad → 400 so agents can retry with fixed payload.
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
	_ = json.NewEncoder(w).Encode(resp)

	// Soft audit trail: record a count summary so operators see high-level
	// telemetry volume without the row-by-row chatter.
	h.logger.Debug("runtime telemetry ingested",
		"tenant_id", agt.TenantID.String(),
		"agent_id", agt.ID.String(),
		"accepted", resp.Accepted,
		"rejected", resp.Rejected,
	)

	_ = middleware.GetRequestID // keep import if unused later
}

func eventErr(i int, msg string) string {
	return "events[" + itoaSmall(i) + "]: " + msg
}

// itoaSmall is a tiny int→string helper so we avoid importing strconv
// for the single place we need it.
func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func nilMapToEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
