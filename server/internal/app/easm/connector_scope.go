package easm

// Connector assets are in scope by default (research/117, RFC-054 §14): the
// public names and addresses a tenant's own connector syncs (a scanner or
// inventory the organization runs) are the organization's, so after a
// successful sync each gets its exact scope entry through the scope service:
// guardrails, the deny list and the signer ledger apply per item, as for any
// bulk add. Only exact entries for the asset's own name are added (never a
// wildcard or range), never for a private or internal name, never for a name
// an active entry already covers, and never while scan approval is Strict.
// The connector's own switch (assets_in_scope) turns it off; entries already
// added stay and are listed on the Scope page with origin connector.

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scope"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TouchedAssets lists the assets the reports of one command wrote
// (*postgres.IngestReportRepository).
type TouchedAssets interface {
	TouchedAssetsByCommand(ctx context.Context, tenantID, commandID shared.ID) ([]shared.ID, error)
}

// AdminNotifier tells the organization's administrators (*scope.Service).
type AdminNotifier interface {
	NotifyAdmins(ctx context.Context, tenantID shared.ID, title, body string)
}

// maxConnectorScopeAssets bounds the assets one sync is read for.
const maxConnectorScopeAssets = 5000

// ConnectorScope adds the exact entries of a connector's synced assets.
type ConnectorScope struct {
	targets  ConfirmScopeTargets
	notify   AdminNotifier
	assets   ActiveGateAssets
	coverage ReviewCoverage
	touched  TouchedAssets
	audit    ScopeJoinAudit
	log      *logger.Logger
}

// NewConnectorScope creates it. audit may be nil; every other dependency is
// required (a nil one adds nothing).
func NewConnectorScope(targets ConfirmScopeTargets, notify AdminNotifier, assets ActiveGateAssets,
	coverage ReviewCoverage, touched TouchedAssets, audit ScopeJoinAudit, log *logger.Logger) *ConnectorScope {
	return &ConnectorScope{targets: targets, notify: notify, assets: assets, coverage: coverage, touched: touched, audit: audit, log: log}
}

func (c *ConnectorScope) ready() bool {
	return c != nil && c.targets != nil && c.notify != nil && c.assets != nil && c.coverage != nil && c.touched != nil && c.log != nil
}

// NotifyConnectorScope tells the administrators, once per connector, that
// its assets are added to scope from its next sync, and where to turn it off.
func (c *ConnectorScope) NotifyConnectorScope(ctx context.Context, tenantID shared.ID, connector string) {
	if !c.ready() {
		return
	}
	c.notify.NotifyAdmins(ctx, tenantID,
		fmt.Sprintf("Assets from %s will be added to scope", connector),
		fmt.Sprintf("From its next sync, the public names and addresses the connector %s syncs get their exact scope entries, so scans may reach them. Turn this off in the connector's settings (Assets are in scope).", connector))
}

// AddConnectorAssets adds the exact entries of the public names and addresses
// the reports of a connector's sync command wrote, and returns how many it
// added. Strict scan approval adds nothing.
func (c *ConnectorScope) AddConnectorAssets(ctx context.Context, tenantID shared.ID, connector string, commandID shared.ID) (int, error) {
	if !c.ready() {
		return 0, nil
	}
	if mode, _ := c.targets.ApprovalPolicy(ctx, tenantID.String()); mode.Normalized() == scangov.ModeStrict {
		return 0, nil
	}
	ids, err := c.touched.TouchedAssetsByCommand(ctx, tenantID, commandID)
	if err != nil {
		return 0, fmt.Errorf("assets of the sync: %w", err)
	}
	if len(ids) > maxConnectorScopeAssets {
		ids = ids[:maxConnectorScopeAssets]
	}
	var items []scope.BulkTargetItem
	seen := map[string]bool{}
	for start := 0; start < len(ids); start += maxGateItems {
		end := min(start+maxGateItems, len(ids))
		found, err := c.assets.GetByIDs(ctx, tenantID, ids[start:end])
		if err != nil {
			return 0, fmt.Errorf("load synced assets: %w", err)
		}
		names := make([]string, 0, len(found))
		planned := make([]scope.BulkTargetItem, 0, len(found))
		for _, a := range found {
			if a == nil {
				continue
			}
			typ, pattern, ok := exactEntry(a)
			if !ok || seen[pattern] {
				continue
			}
			seen[pattern] = true
			planned = append(planned, scope.BulkTargetItem{TargetType: string(typ), Pattern: pattern})
			names = append(names, pattern)
		}
		if len(planned) == 0 {
			continue
		}
		cover, err := c.coverage.CoverOf(ctx, tenantID, names)
		if err != nil {
			return 0, fmt.Errorf("coverage of synced assets: %w", err)
		}
		for _, it := range planned {
			if _, covered := cover[it.Pattern]; !covered {
				items = append(items, it)
			}
		}
	}
	reason := fmt.Sprintf("Synced from the connector %s", connector)
	var added []*scopedom.Target
	for start := 0; start < len(items); start += scope.MaxBulkTargets {
		end := min(start+scope.MaxBulkTargets, len(items))
		outcomes, err := c.targets.CreateTargets(ctx, scope.BulkTargetsInput{
			TenantID: tenantID.String(), Items: items[start:end], Reason: reason, Origin: scopedom.OriginConnector,
		})
		if err != nil {
			return len(added), fmt.Errorf("add connector assets to scope: %w", err)
		}
		for _, o := range outcomes {
			if o.Err == nil && o.Target != nil {
				added = append(added, o.Target)
			}
		}
	}
	if len(added) == 0 {
		return 0, nil
	}
	c.auditAdded(ctx, tenantID, connector, added)
	c.notify.NotifyAdmins(ctx, tenantID,
		fmt.Sprintf("%d scope entries added from %s", len(added), connector),
		fmt.Sprintf("The connector %s synced public names and addresses that were not in scope; each now has its exact scope entry (%s). Turn this off in the connector's settings.",
			connector, samplePatterns(added)))
	return len(added), nil
}

func (c *ConnectorScope) auditAdded(ctx context.Context, tenantID shared.ID, connector string, added []*scopedom.Target) {
	if c.audit == nil {
		return
	}
	for _, t := range added {
		event := auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, t.ID().String()).
			WithResourceName(t.Pattern()).
			WithMessage("Scope entry added: a connector synced the asset").
			WithMetadata("origin", string(scopedom.OriginConnector)).
			WithMetadata("connector", connector).
			WithMetadata("actor", "system")
		if err := c.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String()}, event); err != nil {
			c.log.Warn("connector scope audit failed", "error", logger.SanitizeError(err))
		}
	}
}

// samplePatterns names up to five of the entries.
func samplePatterns(ts []*scopedom.Target) string {
	names := make([]string, 0, 5)
	for _, t := range ts {
		if len(names) == 5 {
			names = append(names, "…")
			break
		}
		names = append(names, t.Pattern())
	}
	return strings.Join(names, ", ")
}
