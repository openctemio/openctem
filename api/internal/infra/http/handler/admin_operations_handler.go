package handler

import (
	"context"
	"database/sql"
	"net/http"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/version"
)

// AdminOperationsHandler serves Console > Operations (RFC-022): the health of
// the installation from the API's own view (build, schema, database, Redis,
// work queues, sensor versions, background controllers). Any admin role reads
// it; it is platform-wide counts and infrastructure facts, no tenant content.
// It works without Prometheus: it reads the database directly and the
// controller gauges from the API's own metrics registry.
type AdminOperationsHandler struct {
	db        *sql.DB
	readOps   func(ctx context.Context) (postgres.OpsSnapshot, error)
	pingRedis func(ctx context.Context) error
	gatherer  prometheus.Gatherer
	shipped   int64
	sdkMin    string
	now       func() time.Time
	logger    *logger.Logger
}

// NewAdminOperationsHandler creates the handler. pingRedis may be nil (no
// Redis configured); gatherer nil uses the default registry.
func NewAdminOperationsHandler(
	db *sql.DB,
	readOps func(ctx context.Context) (postgres.OpsSnapshot, error),
	pingRedis func(ctx context.Context) error,
	gatherer prometheus.Gatherer,
	shippedSchema int64,
	sdkMin string,
	log *logger.Logger,
) *AdminOperationsHandler {
	if gatherer == nil {
		gatherer = prometheus.DefaultGatherer
	}
	return &AdminOperationsHandler{
		db: db, readOps: readOps, pingRedis: pingRedis, gatherer: gatherer,
		shipped: shippedSchema, sdkMin: sdkMin, now: time.Now,
		logger: log.With("handler", "admin_operations"),
	}
}

// AdminOpsComponent is one dependency's check.
type AdminOpsComponent struct {
	OK        bool    `json:"ok"`
	LatencyMS float64 `json:"latency_ms"`
	// Configured is false for an optional dependency that is not set up.
	Configured bool   `json:"configured"`
	Error      string `json:"error,omitempty"`
}

// AdminOpsDatabase is the database check plus the API's connection pool.
type AdminOpsDatabase struct {
	AdminOpsComponent
	OpenConnections int   `json:"open_connections"`
	InUse           int   `json:"in_use"`
	Idle            int   `json:"idle"`
	MaxOpen         int   `json:"max_open"`
	WaitCount       int64 `json:"wait_count"`
}

// AdminOpsSchema compares the applied migration with the shipped one.
type AdminOpsSchema struct {
	Applied int64 `json:"applied"`
	Shipped int64 `json:"shipped"`
	Dirty   bool  `json:"dirty"`
	Known   bool  `json:"known"`
}

// AdminOpsQueues is the state of the work queues.
type AdminOpsQueues struct {
	CommandsPending      int64 `json:"commands_pending"`
	CommandsRunning      int64 `json:"commands_running"`
	CommandOldestSeconds int64 `json:"command_oldest_pending_seconds"`
	ScanRunsOpen         int64 `json:"scan_runs_open"`
	ScanRunsPastDeadline int64 `json:"scan_runs_past_deadline"`
	OutboxPending        int64 `json:"outbox_pending"`
	OutboxFailed         int64 `json:"outbox_failed"`
	OutboxDead           int64 `json:"outbox_dead"`
	OutboxOldestSeconds  int64 `json:"outbox_oldest_pending_seconds"`
}

// AdminOpsSensorGroup counts active sensors of one kind, health and SDK.
type AdminOpsSensorGroup struct {
	Platform     bool   `json:"platform"`
	Health       string `json:"health"`
	ConfigHealth string `json:"config_health,omitempty"`
	SDKVersion   string `json:"sdk_version,omitempty"`
	Count        int64  `json:"count"`
}

// AdminOpsController is one background controller's last run.
type AdminOpsController struct {
	Name          string     `json:"name"`
	Running       bool       `json:"running"`
	LastReconcile *time.Time `json:"last_reconcile_at,omitempty"`
	Errors        float64    `json:"errors_total"`
}

// AdminOperationsResponse is GET /api/v1/admin/operations.
type AdminOperationsResponse struct {
	Build       version.Info          `json:"build"`
	Schema      AdminOpsSchema        `json:"schema"`
	Database    AdminOpsDatabase      `json:"database"`
	Redis       AdminOpsComponent     `json:"redis"`
	Queues      AdminOpsQueues        `json:"queues"`
	Sensors     []AdminOpsSensorGroup `json:"sensors"`
	SDKMin      string                `json:"sdk_min_version,omitempty"`
	Controllers []AdminOpsController  `json:"controllers"`
	CheckedAt   time.Time             `json:"checked_at"`
}

func timed(ctx context.Context, f func(context.Context) error) (float64, error) {
	start := time.Now()
	err := f(ctx)
	return float64(time.Since(start).Microseconds()) / 1000, err
}

// Get handles GET /api/v1/admin/operations.
//
// @Summary      Installation health (platform admin)
// @Description  Build and schema, database (latency, pool), Redis, work queues, active sensors by kind/health/SDK, background controllers' last run. Any admin role; no tenant content.
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  AdminOperationsResponse
// @Router       /admin/operations [get]
func (h *AdminOperationsHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out := AdminOperationsResponse{
		Build: version.Get(), SDKMin: h.sdkMin, CheckedAt: h.now().UTC(),
		Sensors: []AdminOpsSensorGroup{}, Controllers: []AdminOpsController{},
	}

	// Database: a ping and the pool. A failed ping is reported, not an error:
	// this page is how an operator sees that the database is struggling.
	ms, err := timed(ctx, h.db.PingContext)
	out.Database.Configured, out.Database.LatencyMS, out.Database.OK = true, ms, err == nil
	if err != nil {
		h.logger.Warn("operations: database ping", "error", err)
		out.Database.Error = "unreachable"
	}
	st := h.db.Stats()
	out.Database.OpenConnections, out.Database.InUse, out.Database.Idle = st.OpenConnections, st.InUse, st.Idle
	out.Database.MaxOpen, out.Database.WaitCount = st.MaxOpenConnections, st.WaitCount

	if h.pingRedis != nil {
		ms, err := timed(ctx, h.pingRedis)
		out.Redis = AdminOpsComponent{Configured: true, OK: err == nil, LatencyMS: ms}
		if err != nil {
			h.logger.Warn("operations: redis ping", "error", err)
			out.Redis.Error = "unreachable"
		}
	}

	if out.Database.OK {
		ops, err := h.readOps(ctx)
		if err != nil {
			h.logger.Error("operations: read counts", "error", err)
			apierror.InternalServerError("could not read the platform counts").WriteJSON(w)
			return
		}
		out.Schema = AdminOpsSchema{Applied: ops.SchemaVersion, Shipped: h.shipped, Dirty: ops.SchemaDirty, Known: ops.SchemaKnown}
		out.Queues = AdminOpsQueues{
			CommandsPending: ops.CommandsPending, CommandsRunning: ops.CommandsRunning,
			CommandOldestSeconds: int64(ops.CommandOldestPendingSecs),
			ScanRunsOpen:         ops.ScanRunsOpen, ScanRunsPastDeadline: ops.ScanRunsPastDeadline,
			OutboxPending: ops.OutboxPending, OutboxFailed: ops.OutboxFailed, OutboxDead: ops.OutboxDead,
			OutboxOldestSeconds: int64(ops.OutboxOldestPendingSec),
		}
		for _, s := range ops.Sensors {
			out.Sensors = append(out.Sensors, AdminOpsSensorGroup(s))
		}
	} else {
		out.Schema.Shipped = h.shipped
	}

	out.Controllers = controllersFrom(h.gatherer)
	writeJSON(w, http.StatusOK, out)
}

// The controller gauges and counters the controller manager registers.
const (
	metricControllerLast    = "openctem_controller_last_reconcile_timestamp_seconds"
	metricControllerErrors  = "openctem_controller_reconcile_errors_total"
	metricControllerRunning = "openctem_controller_running"
)

// controllersFrom reads each background controller's last run, error count
// and running flag from the metrics registry (no Prometheus server needed).
func controllersFrom(g prometheus.Gatherer) []AdminOpsController {
	families, err := g.Gather()
	if err != nil {
		return []AdminOpsController{}
	}
	byName := map[string]*AdminOpsController{}
	get := func(name string) *AdminOpsController {
		c, ok := byName[name]
		if !ok {
			c = &AdminOpsController{Name: name}
			byName[name] = c
		}
		return c
	}
	for _, f := range families {
		switch f.GetName() {
		case metricControllerLast, metricControllerErrors, metricControllerRunning:
		default:
			continue
		}
		for _, m := range f.GetMetric() {
			name := labelValue(m, "controller")
			if name == "" {
				continue
			}
			c := get(name)
			switch f.GetName() {
			case metricControllerLast:
				if v := m.GetGauge().GetValue(); v > 0 {
					t := time.Unix(int64(v), 0).UTC()
					c.LastReconcile = &t
				}
			case metricControllerErrors:
				c.Errors = m.GetCounter().GetValue()
			case metricControllerRunning:
				c.Running = m.GetGauge().GetValue() > 0
			}
		}
	}
	out := make([]AdminOpsController, 0, len(byName))
	for _, c := range byName {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}
