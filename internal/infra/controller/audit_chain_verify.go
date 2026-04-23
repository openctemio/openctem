package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/internal/metrics"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// chainVerifier is the minimum surface AuditChainVerifyController
// needs from the audit service. Declared locally so tests can mock
// without constructing the full AuditService (which needs a DB).
type chainVerifier interface {
	VerifyChain(ctx context.Context, tenantID shared.ID, limit int) (*audit.ChainVerifyResult, error)
}

// AuditChainVerifyControllerConfig configures AuditChainVerifyController.
type AuditChainVerifyControllerConfig struct {
	// Interval is how often to walk every active tenant's audit chain.
	// Default: 1 hour. A malicious insider has at most (Interval + the
	// duration of this run) before detection, so tune down if your
	// compliance regime demands tighter MTTD for tamper events.
	Interval time.Duration

	// PerTenantLimit is the maximum chain entries walked per tenant per
	// run. Matches the AuditService cap (10_000). Memory-bound; raise
	// only after benchmarking.
	PerTenantLimit int

	Logger *logger.Logger
}

// AuditChainVerifyController periodically walks audit_log_chain for
// every active tenant and surfaces breaks. The audit hash chain
// (migration 000154) is tamper-evident — hashes of prior rows feed
// into each new row — but the guarantee is only useful if someone
// actually runs VerifyChain. An admin endpoint exists
// (GET /api/v1/audit-logs/verify, audit_handler.go) but that is a
// pull path; a malicious insider who deletes rows at 02:00 UTC can
// sit undetected until someone hits that endpoint.
//
// This controller closes the gap by running VerifyChain on a timer.
// On any break it:
//  1. Logs at ERROR level with the tenant, chain_position, and
//     reason so the SIEM can alert on the keyword "audit chain
//     break".
//  2. Exposes a metric via the Manager's metrics sink so alerting
//     systems can threshold on sustained drift.
//
// The FK on audit_log_chain.audit_log_id → audit_logs.id is
// ON DELETE RESTRICT (see 000154_audit_hash_chain.up.sql), so DB-
// level deletion is already blocked. This controller handles the
// out-of-band tamper cases: direct UPDATE of audit_logs fields,
// TRUNCATE, restore-from-different-backup, etc.
type AuditChainVerifyController struct {
	audit   chainVerifier
	tenants tenantdom.Repository
	config  *AuditChainVerifyControllerConfig
	logger  *logger.Logger
}

// NewAuditChainVerifyController wires the controller.
// tenantRepo must expose ListActiveTenantIDs (verified at Reconcile
// time via a type assertion — we don't want a new domain method just
// to thread this through).
func NewAuditChainVerifyController(
	auditSvc *audit.AuditService,
	tenantRepo tenantdom.Repository,
	cfg *AuditChainVerifyControllerConfig,
) *AuditChainVerifyController {
	if cfg == nil {
		cfg = &AuditChainVerifyControllerConfig{}
	}
	if cfg.Interval == 0 {
		cfg.Interval = time.Hour
	}
	if cfg.PerTenantLimit == 0 {
		cfg.PerTenantLimit = 10_000
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.NewNop()
	}
	return &AuditChainVerifyController{
		audit:   auditSvc,
		tenants: tenantRepo,
		config:  cfg,
		logger:  cfg.Logger.With("controller", "audit-chain-verify"),
	}
}

// Name returns the controller name.
func (c *AuditChainVerifyController) Name() string {
	return "audit-chain-verify"
}

// Interval returns the reconciliation interval.
func (c *AuditChainVerifyController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile walks every active tenant's chain once and returns the
// total number of tenants processed. Breaks are surfaced via the
// logger; the return int is the "work unit" counter the controller
// Manager uses for rate / health telemetry, not the break count.
func (c *AuditChainVerifyController) Reconcile(ctx context.Context) (int, error) {
	metrics.AuditChainVerifyRunsTotal.Inc()

	tenantIDs, err := c.tenants.ListActiveTenantIDs(ctx)
	if err != nil {
		return 0, fmt.Errorf("list active tenants: %w", err)
	}

	processed := 0
	totalBreaks := 0
	for _, tid := range tenantIDs {
		if ctx.Err() != nil {
			return processed, ctx.Err()
		}

		res, err := c.audit.VerifyChain(ctx, tid, c.config.PerTenantLimit)
		if err != nil {
			c.logger.Error("audit chain verify call failed",
				"tenant_id", tid.String(),
				"error", err,
			)
			continue
		}
		processed++

		if !res.OK {
			totalBreaks += len(res.Breaks)
			// Emit one structured log per break so SIEM alert rules
			// can fire independently. We deliberately do NOT log the
			// full payload of the broken row — that content itself
			// may be attacker-controlled and we don't want to echo
			// it into the SIEM verbatim.
			for _, b := range res.Breaks {
				c.logger.Error("audit chain break detected",
					"tenant_id", tid.String(),
					"audit_log_id", b.AuditLogID,
					"chain_position", b.ChainPosition,
					"reason", b.Reason,
					// Alerting hint: SIEM rules should match on this
					// keyword + ERROR level to page on-call.
					"alert", "audit_chain_break",
				)
				metrics.AuditChainBreaksTotal.WithLabelValues(tid.String(), b.Reason).Inc()
			}
		}
	}

	if totalBreaks > 0 {
		c.logger.Error("audit chain verification detected breaks this run",
			"tenants_processed", processed,
			"tenants_total", len(tenantIDs),
			"total_breaks", totalBreaks,
		)
	} else {
		c.logger.Debug("audit chain verification clean",
			"tenants_processed", processed,
			"tenants_total", len(tenantIDs),
		)
	}
	return processed, nil
}
