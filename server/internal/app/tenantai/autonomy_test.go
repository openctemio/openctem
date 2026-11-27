package tenantai

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// autonomyRepo adds the autonomy store to the use case fake. race, when
// set, is stored right after the service read the setting (another
// administrator's save landing in between).
type autonomyRepo struct {
	*useCaseRepo
	stored *aidom.Autonomy
	race   *aidom.Autonomy
	writes int
}

func (r *autonomyRepo) GetAutonomy(context.Context, shared.ID) (aidom.Autonomy, bool, error) {
	if r.stored == nil {
		return aidom.Autonomy{}, false, nil
	}
	cur := *r.stored
	if r.race != nil {
		r.stored, r.race = r.race, nil
	}
	return cur, true, nil
}

func (r *autonomyRepo) SaveAutonomy(_ context.Context, _ shared.ID, expected *aidom.Autonomy, next aidom.Autonomy) (bool, error) {
	same := (expected == nil && r.stored == nil) || (expected != nil && r.stored != nil &&
		expected.Paused == r.stored.Paused && sameLimit(expected.PerHour, r.stored.PerHour) && sameLimit(expected.PerDay, r.stored.PerDay))
	if !same {
		return false, nil
	}
	r.stored = &next
	r.writes++
	return true, nil
}

func (r *autonomyRepo) ReserveAutoChange(context.Context, shared.ID, *int, *int, time.Time) (bool, error) {
	return true, nil
}

func intp(v int) *int { return &v }

// A raise decided on a stale read must not be written without the recent
// sign-in: the limit is 10, another administrator lowers it to 5, and a
// save of 8 judged against the old 10 (a "tightening") is refused instead
// of raising 5 to 8 without a step-up.
func TestAutonomy_StaleReadNeverSkipsTheStepUp(t *testing.T) {
	base := newUseCaseRepo()
	repo := &autonomyRepo{useCaseRepo: base, stored: &aidom.Autonomy{PerHour: intp(10), PerDay: intp(500)}}
	svc := NewService(repo, nil, nil, nil, nil, nil)
	gate := &stepUpGate{err: errStepUp}
	svc.SetStepUpGate(gate)
	actx := auditapp.AuditContext{ActorID: shared.NewID().String()}
	tid := shared.NewID().String()

	repo.race = &aidom.Autonomy{PerHour: intp(5), PerDay: intp(500)}
	_, err := svc.SaveAutonomy(context.Background(), tid, AutonomyInput{PerHour: intp(8), PerDay: intp(500)}, actx)
	require.True(t, errors.Is(err, ErrAutonomyChanged), "got %v", err)
	require.Equal(t, 5, *repo.stored.PerHour, "the newer, lower limit stays")
	require.Equal(t, 0, repo.writes)

	// Reloaded, the same save is a raise and needs the recent sign-in.
	_, err = svc.SaveAutonomy(context.Background(), tid, AutonomyInput{PerHour: intp(8), PerDay: intp(500)}, actx)
	require.ErrorIs(t, err, errStepUp)
	require.Equal(t, 0, repo.writes)

	// Pausing on a stale read is refused the same way (reload, one more click).
	repo.race = &aidom.Autonomy{Paused: true, PerHour: intp(5), PerDay: intp(500)}
	_, err = svc.SaveAutonomy(context.Background(), tid, AutonomyInput{Paused: true, PerHour: intp(5), PerDay: intp(500)}, actx)
	require.ErrorIs(t, err, ErrAutonomyChanged)
}
