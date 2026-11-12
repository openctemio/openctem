package unit

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/app/aitriage"
	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/integration"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Every action the catalog offers has a handler once its services exist,
// and no handler is registered for a type the catalog does not list (a
// removed type can never run through a leftover registration).
func TestWorkflowCatalog_EveryActionHasAHandler(t *testing.T) {
	executor := automationsvc.NewWorkflowExecutor(newWfExecMockWorkflowRepo(), newWfExecMockRunRepo(), newWfExecMockNodeRunRepo(), logger.NewNop())
	automationsvc.RegisterAllActionHandlersWithAI(executor,
		&finding.VulnerabilityService{}, nil, &scansvc.Service{}, &integration.IntegrationService{},
		&aitriage.AITriageService{}, nil, nil, logger.NewNop())
	for _, a := range automation.ActionTypes() {
		if !executor.HasActionHandler(a) {
			t.Errorf("action %s is offered but has no handler", a)
		}
	}
	for _, removed := range []automation.ActionType{"assign_team", "update_priority", "run_script", "http_request", "trigger_pipeline"} {
		if removed.IsValid() {
			t.Errorf("removed action %s is still a valid type", removed)
		}
		if executor.HasActionHandler(removed) {
			t.Errorf("removed action %s still has a handler", removed)
		}
	}
	for _, removed := range []automation.TriggerType{"schedule", "finding_age", "finding_updated", "webhook"} {
		if removed.IsValid() {
			t.Errorf("removed trigger %s is still a valid type", removed)
		}
	}
	if automation.NotificationType("pagerduty").IsValid() {
		t.Error("pagerduty is still a valid notification type")
	}
}

// The catalog's entries are the domain lists, each with its permission.
func TestWorkflowCatalog_MatchesDomainLists(t *testing.T) {
	cat := automationsvc.Catalog()
	if len(cat) != len(automation.TriggerTypes())+len(automation.ActionTypes())+len(automation.NotificationTypes()) {
		t.Fatalf("catalog has %d entries", len(cat))
	}
	for _, e := range cat {
		switch e.Kind {
		case automationsvc.CatalogKindTrigger:
			if !automation.TriggerType(e.Type).IsValid() || e.Permission != "" {
				t.Errorf("trigger entry %+v", e)
			}
		case automationsvc.CatalogKindAction:
			if !automation.ActionType(e.Type).IsValid() || e.Permission == "" {
				t.Errorf("action entry %+v", e)
			}
		case automationsvc.CatalogKindNotification:
			if !automation.NotificationType(e.Type).IsValid() || e.Permission == "" {
				t.Errorf("notification entry %+v", e)
			}
		}
	}
}
