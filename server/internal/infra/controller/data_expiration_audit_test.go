package controller

import (
	"context"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
)

type expSuppression struct{ suppression.Repository }

func (expSuppression) ExpireRules(context.Context) (int64, error) { return 0, nil }

type expExclusion struct{ scope.ExclusionRepository }

func (expExclusion) ExpireOld(context.Context) error { return nil }

type countingPruner struct {
	calls int
	cfg   auditapp.RetentionConfig
}

func (p *countingPruner) PruneExpiredChains(_ context.Context, cfg auditapp.RetentionConfig) (auditapp.RetentionResult, error) {
	p.calls++
	p.cfg = cfg
	return auditapp.RetentionResult{}, nil
}

type nopArchive struct{ auditapp.ArchiveStore }

// Audit retention runs by default and hands the storage provider to the
// pruner; AuditRetentionDisabled holds all history.
func TestDataExpiration_AuditRetentionRunsUnlessHeld(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disabled bool
		want     int
	}{{"default", false, 1}, {"held", true, 0}} {
		p := &countingPruner{}
		arch := nopArchive{}
		c := NewDataExpirationController(expSuppression{}, expExclusion{}, p, &DataExpirationControllerConfig{
			AuditArchive: arch, AuditRetentionDisabled: tc.disabled,
		})
		if _, err := c.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if p.calls != tc.want {
			t.Errorf("%s: pruner called %d times, want %d", tc.name, p.calls, tc.want)
		}
		if tc.want == 1 && p.cfg.Store == nil {
			t.Errorf("%s: the storage provider was not passed to the pruner", tc.name)
		}
	}
}
