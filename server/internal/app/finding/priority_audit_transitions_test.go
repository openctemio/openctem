package finding

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The single-finding path (manual create, reclassification sweep) records a
// transition, not every re-confirmation of the same class.
func TestClassifyFinding_AuditsOnlyTransitions(t *testing.T) {
	tenantID := shared.NewID()
	f, a := criticalReachableFinding(t, tenantID)
	repo := &fakePriorityAuditRepo{}
	svc := NewPriorityClassificationService(nil, nil, nil, nil, stubRuleRepo{}, repo, logger.NewNop())
	for i := 0; i < 3; i++ {
		if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
			t.Fatalf("classify: %v", err)
		}
	}
	if len(repo.entries) != 1 || repo.entries[0].PreviousClass != nil {
		t.Fatalf("audit entries = %d, want 1 (the first classification only)", len(repo.entries))
	}
}
