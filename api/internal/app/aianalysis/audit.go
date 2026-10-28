package aianalysis

import (
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
)

func auditEventFor(action audit.Action, resourceID string, sev audit.Severity, meta map[string]any) auditapp.AuditEvent {
	ev := auditapp.NewSuccessEvent(action, audit.ResourceTypeAIAnalysis, resourceID)
	ev.Severity = sev
	ev.Metadata = meta
	ev.Message = string(action)
	return ev
}
