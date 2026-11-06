package handler

import (
	"encoding/json"
	"net/http"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Changes to what sensors scan and run (scope targets, scope exclusions,
// tools and their tenant configuration, scanner templates) are recorded with
// the caller and the state before and after (RFC-040 §5.11). The services
// behind these routes do not audit, so the handlers do, like the scan profile
// and command handlers (scan_change_audit.go).

// auditSnapshot is the audit view of a resource: its API response as a map.
// Nested objects (tool configs, default configs, metadata) have their
// secret-looking values masked the way scanner configs are masked for readers
// who may not see them; top-level fields (ids, names, patterns, statuses) are
// kept as they are. omit names fields left out (large bodies such as
// template content). nil stays nil.
func auditSnapshot(v any, omit ...string) map[string]any {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil
	}
	for _, k := range omit {
		delete(m, k)
	}
	for k, val := range m {
		if nested, ok := val.(map[string]any); ok {
			m[k] = scan.RedactConfigSecrets(nested)
		}
	}
	return m
}

// auditResourceChange records one change with its before and after
// snapshots (either may be nil: nothing before a create, nothing after a
// delete). The change has already happened: a failure is logged.
func auditResourceChange(svc *auditsvc.AuditService, log *logger.Logger, r *http.Request,
	action audit.Action, rt audit.ResourceType, id, name string, before, after map[string]any) {
	event := auditsvc.NewSuccessEvent(action, rt, id).WithResourceName(name)
	if before != nil || after != nil {
		changes := audit.NewChanges()
		changes.Before, changes.After = before, after
		event = event.WithChanges(changes)
	}
	logRequestChange(svc, log, r, event)
}
