package module

import (
	"context"
	"fmt"
	"strings"
	"sync"

	auditapp "github.com/openctemio/api/internal/app/audit"

	"github.com/openctemio/api/pkg/domain/audit"
	moduledom "github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// ModuleRepository interface for module operations.
type ModuleRepository interface {
	ListAllModules(ctx context.Context) ([]*moduledom.Module, error)
	ListActiveModules(ctx context.Context) ([]*moduledom.Module, error)
	GetModuleByID(ctx context.Context, id string) (*moduledom.Module, error)
	GetSubModules(ctx context.Context, parentModuleID string) ([]*moduledom.Module, error)
	ListAllSubModules(ctx context.Context) (map[string][]*moduledom.Module, error)
}

// TenantModuleRepository interface for per-tenant module configuration.
type TenantModuleRepository interface {
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*moduledom.TenantModuleOverride, error)
	UpsertBatch(ctx context.Context, tenantID shared.ID, updates []moduledom.TenantModuleUpdate, updatedBy *shared.ID) error
	DeleteByTenant(ctx context.Context, tenantID shared.ID) error
}

// ModuleService handles module-related business operations.
//
// toggleLocks serialises concurrent UpdateTenantModules calls for the
// same tenant. Without this, two admins flipping related modules at
// the same time could interleave reads and writes such that the
// dependency check passes for each request individually but the
// resulting combined state violates the invariant (TOCTOU). The lock
// is per-tenant so different tenants don't contend.
//
// Caveat: this is an in-process mutex. A multi-replica deployment
// needs a cross-process lock (Redis SETNX, Postgres advisory lock on
// a shared connection, etc.). In the CTEM deployment model the API
// runs as a single replica today; when horizontal scale lands, swap
// this map for the advisory-lock variant.
type ModuleService struct {
	moduleRepo       ModuleRepository
	tenantModuleRepo TenantModuleRepository
	auditService     *auditapp.AuditService
	versionService   *VersionService
	wsBroadcaster    WSBroadcaster
	logger           *logger.Logger

	toggleLocks   map[string]*sync.Mutex
	toggleLocksMu sync.Mutex
}

// WSBroadcaster is the minimal interface ModuleService needs to fan
// out "module.updated" events to subscribers on the tenant channel.
// Defined locally rather than imported from the websocket package to
// keep the dependency direction app→infra (not the other way) and to
// allow nil/no-op in tests.
type WSBroadcaster interface {
	Broadcast(channel string, event any)
}

// NewModuleService creates a new ModuleService.
func NewModuleService(moduleRepo ModuleRepository, log *logger.Logger) *ModuleService {
	return &ModuleService{
		moduleRepo:  moduleRepo,
		logger:      log.With("service", "module"),
		toggleLocks: make(map[string]*sync.Mutex),
	}
}

// tenantToggleLock returns the per-tenant mutex, lazily creating it.
// Lock map guarded by toggleLocksMu; the returned mutex is the one
// callers Lock()/Unlock() on.
func (s *ModuleService) tenantToggleLock(tenantID string) *sync.Mutex {
	s.toggleLocksMu.Lock()
	defer s.toggleLocksMu.Unlock()
	m, ok := s.toggleLocks[tenantID]
	if !ok {
		m = &sync.Mutex{}
		s.toggleLocks[tenantID] = m
	}
	return m
}

// SetTenantModuleRepo sets the tenant module repository.
func (s *ModuleService) SetTenantModuleRepo(repo TenantModuleRepository) {
	s.tenantModuleRepo = repo
}

// SetAuditService sets the audit service for logging module changes.
func (s *ModuleService) SetAuditService(svc *auditapp.AuditService) {
	s.auditService = svc
}

// SetVersionService wires the per-tenant module-version counter used
// for ETag generation and Redis cache key suffixes. Optional —
// without it Get returns 1 forever and ETag never matches (acceptable
// degraded mode, just no caching benefit).
func (s *ModuleService) SetVersionService(v *VersionService) {
	s.versionService = v
}

// SetWSBroadcaster wires the WebSocket fan-out used to push
// "module.updated" events to clients on the tenant channel. Optional —
// without it, mutations still succeed but clients have to wait for the
// next SWR dedup window to see changes.
func (s *ModuleService) SetWSBroadcaster(b WSBroadcaster) {
	s.wsBroadcaster = b
}

// GetTenantModuleVersion returns the current module-config version for
// a tenant. Used by HTTP handlers to construct ETag headers; the
// returned value is opaque to callers (treat as a token, not a count).
func (s *ModuleService) GetTenantModuleVersion(ctx context.Context, tenantID string) int {
	if s.versionService == nil {
		return 1
	}
	return s.versionService.Get(ctx, tenantID)
}

// notifyModuleChange increments the version and broadcasts a
// "module.updated" event to the tenant WebSocket channel. Best-effort
// — failures are logged but never abort the underlying mutation, since
// the tenant_modules write is already persisted by the time we get
// here. Worst case: client sees stale data until next focus / 5-min
// SWR dedup expires.
func (s *ModuleService) notifyModuleChange(ctx context.Context, tenantID string) {
	if s.versionService == nil && s.wsBroadcaster == nil {
		return
	}
	newVersion := 0
	if s.versionService != nil {
		newVersion = s.versionService.Increment(ctx, tenantID)
	}
	if s.wsBroadcaster != nil {
		// Channel naming follows the existing convention used elsewhere
		// in the codebase (tenant:{id}). Event payload includes the
		// fresh version so the client can compare to its cached copy.
		s.wsBroadcaster.Broadcast("tenant:"+tenantID, map[string]any{
			"type":      "module.updated",
			"tenant_id": tenantID,
			"version":   newVersion,
		})
	}
}

// GetTenantEnabledModulesOutput represents the output for GetTenantEnabledModules.
type GetTenantEnabledModulesOutput struct {
	ModuleIDs  []string
	Modules    []*moduledom.Module
	SubModules map[string][]*moduledom.Module
}

// GetTenantEnabledModules returns all enabled modules for a tenant.
// Filters by tenant module overrides if configured.
// Optimized: 2 queries (modules + tenant_modules) instead of 3.
// Sub-modules are extracted from the same ListActiveModules result.
func (s *ModuleService) GetTenantEnabledModules(ctx context.Context, tenantID string) (*GetTenantEnabledModulesOutput, error) {
	allModules, err := s.moduleRepo.ListActiveModules(ctx)
	if err != nil {
		return nil, err
	}

	// Split into top-level and sub-modules from the same query result
	topLevel, subModulesByParent := splitModules(allModules)

	// Get tenant-specific overrides
	disabledModules := s.getTenantDisabledModules(ctx, tenantID)

	// Filter modules: exclude disabled (non-core) top-level modules
	enabledModules := make([]*moduledom.Module, 0, len(topLevel))
	for _, m := range topLevel {
		if disabledModules[m.ID()] && !m.IsCore() {
			continue
		}
		enabledModules = append(enabledModules, m)
	}

	moduleIDs := make([]string, 0, len(enabledModules))
	enabledSet := make(map[string]bool, len(enabledModules))
	for _, m := range enabledModules {
		moduleIDs = append(moduleIDs, m.ID())
		enabledSet[m.ID()] = true
	}

	// Include sub-modules for enabled parents, excluding individually disabled sub-modules
	subModules := make(map[string][]*moduledom.Module, len(subModulesByParent))
	for parentID, subs := range subModulesByParent {
		if enabledSet[parentID] {
			enabledSubs := make([]*moduledom.Module, 0, len(subs))
			for _, sub := range subs {
				if !disabledModules[sub.ID()] {
					enabledSubs = append(enabledSubs, sub)
					moduleIDs = append(moduleIDs, sub.ID())
				}
			}
			if len(enabledSubs) > 0 {
				subModules[parentID] = enabledSubs
			}
		}
	}

	return &GetTenantEnabledModulesOutput{
		ModuleIDs:  moduleIDs,
		Modules:    enabledModules,
		SubModules: subModules,
	}, nil
}

// TenantModuleConfigOutput represents the full module configuration for a tenant.
type TenantModuleConfigOutput struct {
	Modules []*TenantModuleInfo
	Summary TenantModuleSummary
	// Warnings is a best-effort list of soft-dependency degradations
	// introduced by the MOST RECENT toggle. On GET the field is empty;
	// on PATCH it carries the warnings the service decided not to
	// escalate to a blocker. Handlers render these as toast/banner on
	// the Settings → Modules page.
	Warnings []ToggleIssue
}

// TenantModuleInfo combines module metadata with tenant-specific enabled state.
type TenantModuleInfo struct {
	Module     *moduledom.Module
	IsEnabled  bool
	SubModules []*SubModuleInfo
}

// SubModuleInfo combines sub-module metadata with tenant-specific enabled state.
type SubModuleInfo struct {
	Module    *moduledom.Module
	IsEnabled bool
}

// TenantModuleSummary provides counts of module states.
type TenantModuleSummary struct {
	Total    int
	Enabled  int
	Disabled int
	Core     int
}

// GetTenantModuleConfig returns the full module configuration for a tenant admin.
// Optimized: 2 queries (modules + tenant_modules) instead of 3.
func (s *ModuleService) GetTenantModuleConfig(ctx context.Context, tenantID string) (*TenantModuleConfigOutput, error) {
	allModules, err := s.moduleRepo.ListActiveModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list modules: %w", err)
	}

	return s.buildTenantModuleConfig(ctx, tenantID, allModules)
}

// buildTenantModuleConfig builds the tenant module config from pre-loaded modules.
// Separated to allow reuse in UpdateTenantModules (avoids redundant ListActiveModules query).
func (s *ModuleService) buildTenantModuleConfig(ctx context.Context, tenantID string, allModules []*moduledom.Module) (*TenantModuleConfigOutput, error) {
	disabledModules := s.getTenantDisabledModules(ctx, tenantID)
	return s.buildTenantModuleConfigFromMaps(tenantID, allModules, disabledModules)
}

// buildTenantModuleConfigFromMaps is the pure-map variant used by
// UpdateTenantModules, which has already queried tenant_modules once
// for dependency validation. Calling this saves the duplicate
// `getTenantDisabledModules` trip that the plain
// buildTenantModuleConfig would issue.
func (s *ModuleService) buildTenantModuleConfigFromMaps(tenantID string, allModules []*moduledom.Module, disabledModules map[string]bool) (*TenantModuleConfigOutput, error) {
	_ = tenantID // retained in the signature for symmetry; may be used for future scoping

	// Split into top-level and sub-modules from the same query result
	topLevel, subModulesByParent := splitModules(allModules)

	// Build output: only top-level, user-facing modules
	var summary TenantModuleSummary
	modules := make([]*TenantModuleInfo, 0, len(topLevel))

	for _, m := range topLevel {
		// Skip internal/infrastructure modules not shown in sidebar
		if !moduledom.IsUserFacing(m.ID()) {
			continue
		}

		isEnabled := !disabledModules[m.ID()] || m.IsCore()

		// Build sub-module info with INDEPENDENT enabled states.
		// The admin UI needs the sub-module's OWN state (not combined with parent)
		// so that when parent is re-enabled, sub-module states are correctly preserved.
		// The frontend handles parent-off visual override via opacity + pointer-events-none.
		var subInfos []*SubModuleInfo
		if subs, ok := subModulesByParent[m.ID()]; ok {
			subInfos = make([]*SubModuleInfo, 0, len(subs))
			for _, sub := range subs {
				subEnabled := !disabledModules[sub.ID()]
				subInfos = append(subInfos, &SubModuleInfo{
					Module:    sub,
					IsEnabled: subEnabled,
				})
			}
		}

		modules = append(modules, &TenantModuleInfo{
			Module:     m,
			IsEnabled:  isEnabled,
			SubModules: subInfos,
		})

		summary.Total++
		if isEnabled {
			summary.Enabled++
		} else {
			summary.Disabled++
		}
		if m.IsCore() {
			summary.Core++
		}
	}

	return &TenantModuleConfigOutput{
		Modules: modules,
		Summary: summary,
	}, nil
}

// maxModuleUpdatesPerRequest limits batch size to prevent abuse.
const maxModuleUpdatesPerRequest = 50

// UpdateTenantModules toggles modules for a tenant.
func (s *ModuleService) UpdateTenantModules(ctx context.Context, tenantID string, updates []moduledom.TenantModuleUpdate, actx auditapp.AuditContext) (*TenantModuleConfigOutput, error) {
	if s.tenantModuleRepo == nil {
		return nil, fmt.Errorf("%w: tenant module management not configured", shared.ErrInternal)
	}

	if len(updates) > maxModuleUpdatesPerRequest {
		return nil, fmt.Errorf("%w: too many module updates (max %d)", shared.ErrValidation, maxModuleUpdatesPerRequest)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Serialise concurrent toggles on the SAME tenant so the validate→
	// upsert window is atomic. Different tenants don't contend.
	lock := s.tenantToggleLock(tenantID)
	lock.Lock()
	defer lock.Unlock()

	// Pre-load all active modules into a map to avoid N individual GetModuleByID queries
	allModules, loadErr := s.moduleRepo.ListActiveModules(ctx)
	if loadErr != nil {
		return nil, fmt.Errorf("failed to load modules for validation: %w", loadErr)
	}
	moduleMap := make(map[string]*moduledom.Module, len(allModules))
	for _, m := range allModules {
		moduleMap[m.ID()] = m
	}

	// Build the enabled-module set AFTER the proposed updates, so the
	// dependency check sees the target state, not the current state. This
	// matters when a single request both disables X and the modules that
	// soft/hard depend on X — the request as a whole is valid even though
	// mid-way the dependent is still in the updates queue.
	disabled := s.getTenantDisabledModules(ctx, tenantID)
	enabledAfter := make(map[string]bool, len(allModules))
	for _, m := range allModules {
		enabledAfter[m.ID()] = m.IsActive() && !disabled[m.ID()]
	}
	for _, u := range updates {
		enabledAfter[u.ModuleID] = u.IsEnabled
	}

	// Validate all module IDs against pre-loaded map (0 additional queries)
	var disabledNames, enabledNames []string
	var collectedWarnings []ToggleIssue
	for _, u := range updates {
		m, exists := moduleMap[u.ModuleID]
		if !exists {
			return nil, fmt.Errorf("%w: unknown module: %s", shared.ErrValidation, u.ModuleID)
		}

		if !m.IsActive() {
			return nil, fmt.Errorf("%w: module '%s' is not available", moduledom.ErrModuleNotAvailable, u.ModuleID)
		}

		if !u.IsEnabled && m.IsCore() {
			return nil, fmt.Errorf("%w: '%s' is a core module and cannot be disabled", moduledom.ErrCoreModuleCannotBeDisabled, m.Name())
		}
		// Mandatory modules (operational essentials like `agents` for
		// data ingestion) — disabling them silently breaks the platform.
		// Reject so an admin doesn't accidentally DoS the tenant via
		// the toggle UI. Distinct error from core so UI can render a
		// targeted message.
		if !u.IsEnabled && moduledom.MandatoryModuleIDs[u.ModuleID] {
			return nil, fmt.Errorf("%w: '%s' is a mandatory module — disabling would break platform functionality (data ingestion, alerts, RBAC)", shared.ErrValidation, m.Name())
		}

		// Dependency check — platform-wide static graph in
		// pkg/domain/module/dependency.go. Reject if any hard-dependent
		// module remains enabled in the post-update state. Deps that
		// reference modules NOT present in the registry (e.g.
		// platform-edition mismatch, or a dep migration that hasn't
		// run yet) are skipped — we cannot block on something the
		// deployment doesn't know about. Returns a structured
		// ToggleError the HTTP handler can serialise as JSON.
		if !u.IsEnabled {
			blockers, warnings := moduledom.CanDisable(u.ModuleID, enabledAfter)
			issues := collectBlockerIssues(blockers, moduleMap)
			if len(issues) > 0 {
				return nil, &ToggleError{
					ModuleID:   u.ModuleID,
					ModuleName: m.Name(),
					Action:     "disable",
					Blockers:   issues,
				}
			}
			// Soft warnings — not fatal, just surface them.
			collectedWarnings = append(collectedWarnings, collectWarningIssues(warnings, moduleMap)...)
		} else {
			// Enabling — verify required hard deps are enabled too.
			missing := moduledom.RequiredToEnable(u.ModuleID, enabledAfter)
			issues := collectRequiredIssues(missing, moduleMap)
			if len(issues) > 0 {
				return nil, &ToggleError{
					ModuleID:   u.ModuleID,
					ModuleName: m.Name(),
					Action:     "enable",
					Required:   issues,
				}
			}
		}

		if u.IsEnabled {
			enabledNames = append(enabledNames, m.Name())
		} else {
			disabledNames = append(disabledNames, m.Name())
		}
	}

	// Parse updatedBy from audit context
	var updatedBy *shared.ID
	if actx.ActorID != "" {
		uid, uidErr := shared.IDFromString(actx.ActorID)
		if uidErr == nil {
			updatedBy = &uid
		}
	}

	// Upsert
	if err := s.tenantModuleRepo.UpsertBatch(ctx, parsedTenantID, updates, updatedBy); err != nil {
		return nil, fmt.Errorf("failed to update tenant modules: %w", err)
	}

	// Audit log
	s.logModuleAudit(ctx, actx, tenantID, enabledNames, disabledNames)
	// Bump version + WS broadcast so other tabs/clients invalidate
	// their SWR cache and refetch immediately.
	s.notifyModuleChange(ctx, tenantID)

	// Re-derive the disabled set from the applied updates instead of
	// re-querying the DB (saves one round-trip per toggle request).
	for _, u := range updates {
		disabled[u.ModuleID] = !u.IsEnabled
	}
	out, buildErr := s.buildTenantModuleConfigFromMaps(tenantID, allModules, disabled)
	if buildErr != nil {
		return nil, buildErr
	}
	out.Warnings = collectedWarnings
	return out, nil
}

// ValidateToggle runs the same dependency gate as UpdateTenantModules
// but WITHOUT persisting. The UI calls this from the module-toggle UI
// to preview blockers/warnings before the user commits. Hit path:
//
//	POST /api/v1/tenants/{t}/settings/modules/validate
func (s *ModuleService) ValidateToggle(ctx context.Context, tenantID string, updates []moduledom.TenantModuleUpdate) (*ValidationIssues, error) {
	if s.tenantModuleRepo == nil {
		return nil, fmt.Errorf("%w: tenant module management not configured", shared.ErrInternal)
	}
	if len(updates) > maxModuleUpdatesPerRequest {
		return nil, fmt.Errorf("%w: too many module updates (max %d)", shared.ErrValidation, maxModuleUpdatesPerRequest)
	}
	if _, err := shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	allModules, err := s.moduleRepo.ListActiveModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("load modules: %w", err)
	}
	moduleMap := make(map[string]*moduledom.Module, len(allModules))
	for _, m := range allModules {
		moduleMap[m.ID()] = m
	}
	disabled := s.getTenantDisabledModules(ctx, tenantID)
	enabledAfter := make(map[string]bool, len(allModules))
	for _, m := range allModules {
		enabledAfter[m.ID()] = m.IsActive() && !disabled[m.ID()]
	}
	for _, u := range updates {
		enabledAfter[u.ModuleID] = u.IsEnabled
	}

	issues := &ValidationIssues{}
	for _, u := range updates {
		m, ok := moduleMap[u.ModuleID]
		if !ok || !m.IsActive() {
			continue
		}
		if !u.IsEnabled {
			if m.IsCore() {
				// Surface as blocker with an explicit reason so the UI
				// can render the same dialog.
				issues.Blockers = append(issues.Blockers, ToggleIssue{
					ModuleID: u.ModuleID,
					Name:     m.Name(),
					Reason:   "core module — cannot be disabled",
				})
				continue
			}
			blockers, warnings := moduledom.CanDisable(u.ModuleID, enabledAfter)
			issues.Blockers = append(issues.Blockers, collectBlockerIssues(blockers, moduleMap)...)
			issues.Warnings = append(issues.Warnings, collectWarningIssues(warnings, moduleMap)...)
		} else {
			missing := moduledom.RequiredToEnable(u.ModuleID, enabledAfter)
			issues.Required = append(issues.Required, collectRequiredIssues(missing, moduleMap)...)
		}
	}
	return issues, nil
}

func collectBlockerIssues(blockers []moduledom.ToggleBlocker, moduleMap map[string]*moduledom.Module) []ToggleIssue {
	out := make([]ToggleIssue, 0, len(blockers))
	seen := make(map[string]bool, len(blockers))
	for _, b := range blockers {
		if seen[b.DependentModuleID] {
			continue
		}
		dep, ok := moduleMap[b.DependentModuleID]
		if !ok {
			continue
		}
		seen[b.DependentModuleID] = true
		out = append(out, ToggleIssue{
			ModuleID: b.DependentModuleID,
			Name:     dep.Name(),
			Reason:   b.Reason,
		})
	}
	return out
}

func collectWarningIssues(warnings []moduledom.ToggleWarning, moduleMap map[string]*moduledom.Module) []ToggleIssue {
	out := make([]ToggleIssue, 0, len(warnings))
	seen := make(map[string]bool, len(warnings))
	for _, w := range warnings {
		if seen[w.DependentModuleID] {
			continue
		}
		dep, ok := moduleMap[w.DependentModuleID]
		if !ok {
			continue
		}
		seen[w.DependentModuleID] = true
		out = append(out, ToggleIssue{
			ModuleID: w.DependentModuleID,
			Name:     dep.Name(),
			Reason:   w.Reason,
		})
	}
	return out
}

func collectRequiredIssues(missing []moduledom.Dependency, moduleMap map[string]*moduledom.Module) []ToggleIssue {
	out := make([]ToggleIssue, 0, len(missing))
	for _, d := range missing {
		dep, ok := moduleMap[d.ModuleID]
		if !ok {
			continue
		}
		out = append(out, ToggleIssue{
			ModuleID: d.ModuleID,
			Name:     dep.Name(),
			Reason:   d.Reason,
		})
	}
	return out
}

// ResetTenantModules resets all module overrides for a tenant (all modules enabled).
func (s *ModuleService) ResetTenantModules(ctx context.Context, tenantID string, actx auditapp.AuditContext) (*TenantModuleConfigOutput, error) {
	if s.tenantModuleRepo == nil {
		return nil, fmt.Errorf("%w: tenant module management not configured", shared.ErrInternal)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if err := s.tenantModuleRepo.DeleteByTenant(ctx, parsedTenantID); err != nil {
		return nil, fmt.Errorf("failed to reset tenant modules: %w", err)
	}

	// Audit log
	s.logModuleAudit(ctx, actx, tenantID, nil, nil)
	s.notifyModuleChange(ctx, tenantID)

	return s.GetTenantModuleConfig(ctx, tenantID)
}

func (s *ModuleService) logModuleAudit(ctx context.Context, actx auditapp.AuditContext, tenantID string, enabled, disabled []string) {
	if s.auditService == nil {
		return
	}

	actx.TenantID = tenantID

	var msgParts []string
	if len(enabled) > 0 {
		msgParts = append(msgParts, "enabled "+strings.Join(enabled, ", "))
	}
	if len(disabled) > 0 {
		msgParts = append(msgParts, "disabled "+strings.Join(disabled, ", "))
	}

	var msg string
	if len(msgParts) > 0 {
		msg = "Modules updated: " + strings.Join(msgParts, "; ")
	} else {
		msg = "Modules reset to defaults"
	}

	event := auditapp.NewSuccessEvent(audit.ActionTenantModulesUpdated, audit.ResourceTypeTenant, tenantID).
		WithMessage(msg).
		WithSeverity(audit.SeverityMedium)

	if len(enabled) > 0 {
		event = event.WithMetadata("enabled", strings.Join(enabled, ", "))
	}
	if len(disabled) > 0 {
		event = event.WithMetadata("disabled", strings.Join(disabled, ", "))
	}

	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log module audit event", "error", err)
	}
}

// splitModules separates a flat list of modules into top-level modules
// and sub-modules grouped by parent ID. This avoids a separate DB query
// since ListActiveModules already returns both.
func splitModules(allModules []*moduledom.Module) ([]*moduledom.Module, map[string][]*moduledom.Module) {
	topLevel := make([]*moduledom.Module, 0, len(allModules))
	subByParent := make(map[string][]*moduledom.Module)

	for _, m := range allModules {
		if m.IsSubModule() {
			parentID := *m.ParentModuleID()
			subByParent[parentID] = append(subByParent[parentID], m)
		} else {
			topLevel = append(topLevel, m)
		}
	}

	return topLevel, subByParent
}

// getTenantDisabledModules returns a set of module IDs disabled by the tenant.
func (s *ModuleService) getTenantDisabledModules(ctx context.Context, tenantID string) map[string]bool {
	disabled := make(map[string]bool)
	if s.tenantModuleRepo == nil {
		return disabled
	}

	parsedID, parseErr := shared.IDFromString(tenantID)
	if parseErr != nil {
		return disabled
	}

	overrides, err := s.tenantModuleRepo.ListByTenant(ctx, parsedID)
	if err != nil {
		s.logger.Warn("failed to get tenant module overrides", "tenant_id", tenantID, "error", err)
		return disabled
	}

	for _, o := range overrides {
		if !o.IsEnabled {
			disabled[o.ModuleID] = true
		}
	}
	return disabled
}

// ListActiveModules returns all active modules.
func (s *ModuleService) ListActiveModules(ctx context.Context) ([]*moduledom.Module, error) {
	return s.moduleRepo.ListActiveModules(ctx)
}

// GetModule retrieves a module by ID.
func (s *ModuleService) GetModule(ctx context.Context, moduleID string) (*moduledom.Module, error) {
	return s.moduleRepo.GetModuleByID(ctx, moduleID)
}

// DependencyEdgeOutput is the UI-facing shape of one dependency edge.
type DependencyEdgeOutput struct {
	From   string `json:"from"`             // Module that depends on the target.
	To     string `json:"to"`               // Target module required by From.
	Type   string `json:"type"`             // "hard" or "soft".
	Reason string `json:"reason,omitempty"` // Human-readable explanation.
}

// DependencyGraphOutput is returned by GetDependencyGraph. Flat edge list
// so the UI can render the graph with any layout library without
// re-shaping the server response.
type DependencyGraphOutput struct {
	Edges []DependencyEdgeOutput `json:"edges"`
}

// GetDependencyGraph returns the static module dependency graph. The
// graph is read from pkg/domain/module/dependency.go (platform-wide
// spec, does not change per tenant or at runtime). The UI uses this
// to render the Settings → Modules page with dependency badges and
// to show "disabling X will also affect Y, Z" confirmation dialogs.
func (s *ModuleService) GetDependencyGraph(_ context.Context) *DependencyGraphOutput {
	out := &DependencyGraphOutput{}
	for dependent, deps := range moduledom.ModuleDependencies {
		for _, d := range deps {
			out.Edges = append(out.Edges, DependencyEdgeOutput{
				From:   dependent,
				To:     d.ModuleID,
				Type:   string(d.Type),
				Reason: d.Reason,
			})
		}
	}
	return out
}

// =============================================================================
// MODULE PRESETS — bundle curated module sets admins apply instead of
// toggling ~100 modules one by one. Presets are defined statically in
// pkg/domain/module/presets.go; this file exposes them via service
// methods for the HTTP handler.
// =============================================================================

// ModulePresetOutput is the API-facing shape of one preset.
type ModulePresetOutput struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	TargetPersona  string   `json:"target_persona"`
	Icon           string   `json:"icon"`
	KeyOutcomes    []string `json:"key_outcomes"`
	RecommendedFor []string `json:"recommended_for"`
	ModuleCount    int      `json:"module_count"` // resolved count incl. core + transitive
}

// PresetDiffOutput describes what would change if a preset were applied.
type PresetDiffOutput struct {
	PresetID    string              `json:"preset_id"`
	PresetName  string              `json:"preset_name"`
	ToEnable    []ModuleRefOutput   `json:"to_enable"`
	ToDisable   []ModuleRefOutput   `json:"to_disable"`
	Unchanged   int                 `json:"unchanged"`
	TotalAfter  int                 `json:"total_after"`
	AuditNotice string              `json:"audit_notice,omitempty"`
}

// ModuleRefOutput is a thin (id, name) pair used in diff listings.
type ModuleRefOutput struct {
	ModuleID string `json:"module_id"`
	Name     string `json:"name"`
}

// ListModulePresets returns every preset registered in the domain
// catalogue, with the module count already resolved so the UI can
// render "Enables X modules" badges without a second round-trip.
func (s *ModuleService) ListModulePresets(_ context.Context) []ModulePresetOutput {
	out := make([]ModulePresetOutput, 0, len(moduledom.ModulePresets))
	for i := range moduledom.ModulePresets {
		p := &moduledom.ModulePresets[i]
		resolved := moduledom.ResolvePresetModules(p)
		out = append(out, ModulePresetOutput{
			ID:             p.ID,
			Name:           p.Name,
			Description:    p.Description,
			TargetPersona:  p.TargetPersona,
			Icon:           p.Icon,
			KeyOutcomes:    append([]string(nil), p.KeyOutcomes...),
			RecommendedFor: append([]string(nil), p.RecommendedFor...),
			ModuleCount:    len(resolved),
		})
	}
	return out
}

// PreviewPreset computes the diff between the tenant's current module
// state and the state that would result from applying the preset.
// Read-only — never mutates tenant_modules.
func (s *ModuleService) PreviewPreset(ctx context.Context, tenantID, presetID string) (*PresetDiffOutput, error) {
	preset := moduledom.FindPreset(presetID)
	if preset == nil {
		return nil, fmt.Errorf("%w: unknown preset: %s", shared.ErrNotFound, presetID)
	}
	return s.buildPresetDiff(ctx, tenantID, preset)
}

// ApplyPreset materialises the preset into tenant_modules. Diff is
// computed, then turned into UpdateTenantModules calls so the
// dependency-graph validation and audit logging run exactly as if the
// admin had toggled each module manually. Same locking semantics too.
//
// If tenantID is empty or the audit context has no actor, this still
// works for the initial tenant-creation code path — the caller is
// expected to have populated actx in that case.
func (s *ModuleService) ApplyPreset(ctx context.Context, tenantID, presetID string, actx auditapp.AuditContext) (*TenantModuleConfigOutput, error) {
	preset := moduledom.FindPreset(presetID)
	if preset == nil {
		return nil, fmt.Errorf("%w: unknown preset: %s", shared.ErrNotFound, presetID)
	}

	diff, err := s.buildPresetDiff(ctx, tenantID, preset)
	if err != nil {
		return nil, err
	}

	// No-op when current state already matches — skip the round-trip.
	if len(diff.ToEnable) == 0 && len(diff.ToDisable) == 0 {
		return s.GetTenantModuleConfig(ctx, tenantID)
	}

	// Build the update set. We explicitly set every module the preset
	// touches, rather than sending only "is_enabled=false" rows, so the
	// repo stores a positive row for each formerly-disabled module the
	// preset is re-enabling.
	updates := make([]moduledom.TenantModuleUpdate, 0, len(diff.ToEnable)+len(diff.ToDisable))
	for _, r := range diff.ToEnable {
		updates = append(updates, moduledom.TenantModuleUpdate{ModuleID: r.ModuleID, IsEnabled: true})
	}
	for _, r := range diff.ToDisable {
		updates = append(updates, moduledom.TenantModuleUpdate{ModuleID: r.ModuleID, IsEnabled: false})
	}

	// Stamp the preset ID into the audit metadata so operators can
	// later grep "which tenants applied the compliance preset".
	cfg, err := s.UpdateTenantModules(ctx, tenantID, updates, actx)
	if err != nil {
		return nil, err
	}
	s.logPresetApplied(ctx, actx, tenantID, preset)
	return cfg, nil
}

// buildPresetDiff is shared by PreviewPreset and ApplyPreset. It loads
// the active module catalogue + the tenant's current disabled set,
// then classifies every module into enable / disable / unchanged.
func (s *ModuleService) buildPresetDiff(ctx context.Context, tenantID string, p *moduledom.ModulePreset) (*PresetDiffOutput, error) {
	if _, err := shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	allModules, err := s.moduleRepo.ListActiveModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load modules: %w", err)
	}

	nameOf := make(map[string]string, len(allModules))
	for _, m := range allModules {
		nameOf[m.ID()] = m.Name()
	}

	target := moduledom.ResolvePresetModules(p) // what the preset wants
	// Sub-module inheritance: if the parent ("assets", "ai_triage",
	// "integrations") is enabled in the preset, every "<parent>.<sub>"
	// sub-module of that parent is implicitly enabled too. Avoids
	// forcing every preset to enumerate 24 `assets.*` types just to
	// keep them on. Explicit list in the preset still wins (a future
	// preset could opt-out specific sub-modules by listing them in a
	// dedicated "disabled" field; not needed yet).
	for _, m := range allModules {
		id := m.ID()
		if !strings.Contains(id, ".") {
			continue
		}
		parent := strings.SplitN(id, ".", 2)[0]
		if target[parent] {
			target[id] = true
		}
	}
	disabledNow := s.getTenantDisabledModules(ctx, tenantID)

	diff := &PresetDiffOutput{
		PresetID:   p.ID,
		PresetName: p.Name,
		// Initialise as empty slices (not nil) so JSON serialises as
		// [] rather than null. UI iterates these without null-checks.
		ToEnable:  []ModuleRefOutput{},
		ToDisable: []ModuleRefOutput{},
	}

	for _, m := range allModules {
		id := m.ID()
		wantEnabled := target[id]
		currentlyEnabled := m.IsActive() && !disabledNow[id]

		switch {
		case wantEnabled && !currentlyEnabled:
			diff.ToEnable = append(diff.ToEnable, ModuleRefOutput{ModuleID: id, Name: m.Name()})
		case !wantEnabled && currentlyEnabled && !m.IsCore():
			// Never include core modules in ToDisable — they cannot be
			// turned off by the user anyway. Surfacing them would give
			// admins the false impression the preset will silence them.
			diff.ToDisable = append(diff.ToDisable, ModuleRefOutput{ModuleID: id, Name: m.Name()})
		default:
			diff.Unchanged++
		}

		if wantEnabled {
			diff.TotalAfter++
		}
	}

	return diff, nil
}

// logPresetApplied records the preset choice separately from the
// underlying toggle audit, so auditors can reconstruct "admin applied
// VM Essentials" without parsing toggle-level rows.
func (s *ModuleService) logPresetApplied(ctx context.Context, actx auditapp.AuditContext, tenantID string, p *moduledom.ModulePreset) {
	if s.auditService == nil {
		return
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantModulesUpdated, audit.ResourceTypeTenant, tenantID).
		WithMessage("Module preset applied: " + p.Name).
		WithSeverity(audit.SeverityMedium).
		WithMetadata("preset_id", p.ID).
		WithMetadata("preset_name", p.Name)
	s.auditService.LogEvent(ctx, actx, event)
}
