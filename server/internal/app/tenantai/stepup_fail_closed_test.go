package tenantai

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// stepUpRepo carries every AI policy store the loosening paths write.
type stepUpRepo struct {
	*autonomyRepo
	triageWrites int
}

func (r *stepUpRepo) SaveAutoTriagePolicy(context.Context, shared.ID, tenant.AutoTriagePolicy) error {
	r.triageWrites++
	return nil
}

func (r *stepUpRepo) writes() int { return r.saves + r.autonomyRepo.writes + r.triageWrites }

// Every loosening of an AI policy asks for a recent re-authentication. A
// service with no step-up check wired refuses the loosening (fail closed)
// instead of making it without the check; a gate that refuses (an actor
// without a recent sign-in) refuses it too; a passing gate lets it through.
func TestAILoosening_StepUpFailsClosed(t *testing.T) {
	loosen := map[string]func(*Service, string, auditapp.AuditContext) error{
		"use case auto-apply": func(s *Service, tid string, a auditapp.AuditContext) error {
			_, err := s.SaveUseCase(context.Background(), tid, "triage", UseCaseInput{Mode: "auto_apply", Ceiling: "internal", MinConfidence: 0.9}, a)
			return err
		},
		"autonomy limit raised": func(s *Service, tid string, a auditapp.AuditContext) error {
			_, err := s.SaveAutonomy(context.Background(), tid, AutonomyInput{PerHour: intp(50), PerDay: intp(500)}, a)
			return err
		},
		"auto triage turned on": func(s *Service, tid string, a auditapp.AuditContext) error {
			_, err := s.SaveAutoTriage(context.Background(), tid, tenant.AutoTriagePolicy{Enabled: true, Severities: []string{"low"}}, a)
			return err
		},
	}
	for name, run := range loosen {
		t.Run(name, func(t *testing.T) {
			setup := func() (*Service, *stepUpRepo, string) {
				base := newUseCaseRepo()
				repo := &stepUpRepo{autonomyRepo: &autonomyRepo{useCaseRepo: base, stored: &aidom.Autonomy{PerHour: intp(10), PerDay: intp(500)}}}
				tid := shared.NewID()
				on := tenant.AISettings{}
				on.SetOptIn(true, "admin", time.Now())
				base.rows[tid] = on
				return NewService(repo, nil, nil, nil, nil, nil), repo, tid.String()
			}
			a := auditapp.AuditContext{ActorID: shared.NewID().String()}

			// No step-up check wired: refused, nothing written.
			svc, repo, tid := setup()
			require.ErrorIs(t, run(svc, tid, a), ErrStepUpUnavailable)
			require.Zero(t, repo.writes())

			// A member without a recent sign-in: refused, nothing written.
			svc, repo, tid = setup()
			svc.SetStepUpGate(&stepUpGate{err: errStepUp})
			require.ErrorIs(t, run(svc, tid, a), errStepUp)
			require.Zero(t, repo.writes())

			// Recent sign-in: the loosening is saved.
			svc, repo, tid = setup()
			gate := &stepUpGate{}
			svc.SetStepUpGate(gate)
			require.NoError(t, run(svc, tid, a))
			require.Equal(t, 1, gate.calls)
			require.Equal(t, 1, repo.writes())
		})
	}
}
