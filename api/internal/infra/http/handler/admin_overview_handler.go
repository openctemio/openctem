package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AdminOverviewHandler serves the console's attention queue (Console >
// Overview, RFC-022): what needs a platform administrator now. Any admin role
// reads it. It returns counts and the names of a few organizations that need
// an owner; nothing from inside an organization, and no administrator emails
// (the roster stays super-admin only).
type AdminOverviewHandler struct {
	readCounts func(ctx context.Context, now time.Time) (postgres.AdminOverviewCounts, error)
	readOps    func(ctx context.Context) (postgres.OpsSnapshot, error)
	admins     adminActiveLister
	// shippedSchema is the newest migration this binary ships (0: unknown).
	shippedSchema int64
	now           func() time.Time
	logger        *logger.Logger
}

type adminActiveLister interface {
	ListActive(ctx context.Context) ([]*admin.AdminUser, error)
}

// NewAdminOverviewHandler creates the handler.
func NewAdminOverviewHandler(
	readCounts func(ctx context.Context, now time.Time) (postgres.AdminOverviewCounts, error),
	readOps func(ctx context.Context) (postgres.OpsSnapshot, error),
	admins adminActiveLister,
	shippedSchema int64,
	log *logger.Logger,
) *AdminOverviewHandler {
	return &AdminOverviewHandler{
		readCounts: readCounts, readOps: readOps, admins: admins,
		shippedSchema: shippedSchema, now: time.Now,
		logger: log.With("handler", "admin_overview"),
	}
}

// AdminOverviewOrgRef names one organization in an attention item.
type AdminOverviewOrgRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AdminOverviewOrganizations is the organization part of the overview.
type AdminOverviewOrganizations struct {
	Total              int64                 `json:"total"`
	WithoutOwner       int64                 `json:"without_owner"`
	WithoutOwnerSample []AdminOverviewOrgRef `json:"without_owner_sample"`
}

// AdminOverviewSecurity is the administrator-security part of the overview.
type AdminOverviewSecurity struct {
	BreakGlassSignIns7d    int64 `json:"break_glass_sign_ins_7d"`
	FailedAdminActions24h  int64 `json:"failed_admin_actions_24h"`
	BreakGlassTestsOverdue int   `json:"break_glass_tests_overdue"`
}

// AdminOverviewSensors counts the active platform sensors by health.
type AdminOverviewSensors struct {
	Total   int64 `json:"total"`
	Online  int64 `json:"online"`
	Offline int64 `json:"offline"`
}

// AdminOverviewPlatform is the platform-health part of the overview.
type AdminOverviewPlatform struct {
	SchemaVersion        int64                `json:"schema_version"`
	SchemaShipped        int64                `json:"schema_shipped"`
	SchemaDirty          bool                 `json:"schema_dirty"`
	SchemaKnown          bool                 `json:"schema_known"`
	PlatformSensors      AdminOverviewSensors `json:"platform_sensors"`
	CommandsPending      int64                `json:"commands_pending"`
	CommandOldestSeconds int64                `json:"command_oldest_pending_seconds"`
	ScanRunsPastDeadline int64                `json:"scan_runs_past_deadline"`
	OutboxFailed         int64                `json:"outbox_failed"`
	OutboxDead           int64                `json:"outbox_dead"`
}

// AdminOverviewResponse is GET /api/v1/admin/overview.
type AdminOverviewResponse struct {
	Organizations AdminOverviewOrganizations `json:"organizations"`
	Security      AdminOverviewSecurity      `json:"security"`
	Platform      AdminOverviewPlatform      `json:"platform"`
	GeneratedAt   time.Time                  `json:"generated_at"`
}

// Get returns the attention counts.
//
// @Summary      Console overview (attention queue)
// @Description  Counts a platform administrator should act on: organizations without an owner, emergency-access sign-ins, failed administrator actions, overdue break-glass tests, schema drift, offline platform sensors, stuck work. Any admin role.
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  AdminOverviewResponse
// @Router       /admin/overview [get]
func (h *AdminOverviewHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	now := h.now()

	counts, err := h.readCounts(ctx, now)
	if err != nil {
		h.logger.Error("read overview counts", "error", err)
		apierror.InternalServerError("could not read the overview").WriteJSON(w)
		return
	}
	ops, err := h.readOps(ctx)
	if err != nil {
		h.logger.Error("read platform counts", "error", err)
		apierror.InternalServerError("could not read the overview").WriteJSON(w)
		return
	}
	overdue := 0
	if h.admins != nil {
		active, err := h.admins.ListActive(ctx)
		if err != nil {
			h.logger.Error("list administrators", "error", err)
			apierror.InternalServerError("could not read the overview").WriteJSON(w)
			return
		}
		for _, a := range active {
			if a.BreakGlassTestOverdue(now) {
				overdue++
			}
		}
	}

	writeJSON(w, http.StatusOK, buildAdminOverview(counts, ops, overdue, h.shippedSchema, now))
}

func buildAdminOverview(c postgres.AdminOverviewCounts, ops postgres.OpsSnapshot, overdue int, shipped int64, now time.Time) AdminOverviewResponse {
	sample := make([]AdminOverviewOrgRef, 0, len(c.OrganizationsWithoutOwnerSample))
	for _, o := range c.OrganizationsWithoutOwnerSample {
		sample = append(sample, AdminOverviewOrgRef(o))
	}
	var sensors AdminOverviewSensors
	for _, s := range ops.Sensors {
		if !s.Platform {
			continue
		}
		sensors.Total += s.Count
		switch s.Health {
		case "online":
			sensors.Online += s.Count
		case "offline", "stale", "error":
			sensors.Offline += s.Count
		}
	}
	return AdminOverviewResponse{
		Organizations: AdminOverviewOrganizations{
			Total: c.Organizations, WithoutOwner: c.OrganizationsWithoutOwner, WithoutOwnerSample: sample,
		},
		Security: AdminOverviewSecurity{
			BreakGlassSignIns7d:    c.BreakGlassSignIns7d,
			FailedAdminActions24h:  c.FailedAdminActions24h,
			BreakGlassTestsOverdue: overdue,
		},
		Platform: AdminOverviewPlatform{
			SchemaVersion:        ops.SchemaVersion,
			SchemaShipped:        shipped,
			SchemaDirty:          ops.SchemaDirty,
			SchemaKnown:          ops.SchemaKnown,
			PlatformSensors:      sensors,
			CommandsPending:      ops.CommandsPending,
			CommandOldestSeconds: int64(ops.CommandOldestPendingSecs),
			ScanRunsPastDeadline: ops.ScanRunsPastDeadline,
			OutboxFailed:         ops.OutboxFailed,
			OutboxDead:           ops.OutboxDead,
		},
		GeneratedAt: now.UTC(),
	}
}
