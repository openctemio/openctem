package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fixedProgramRules struct{ err error }

func (f fixedProgramRules) JobRules(context.Context, shared.ID, []string, time.Time) (*bp.JobRules, error) {
	return nil, f.err
}

func TestRefuseProgramRules(t *testing.T) {
	ctx := context.Background()
	s := &Service{}
	if err := s.refuseProgramRules(ctx, shared.NewID(), []string{"a.example"}); err != nil {
		t.Fatalf("not wired: %v", err)
	}
	cases := []struct {
		err  error
		want error
	}{
		{nil, nil},
		{bp.ErrRulesConflict, bp.ErrRulesConflict},
		{errors.New("db down"), shared.ErrValidation},
	}
	for _, c := range cases {
		s.SetProgramRules(fixedProgramRules{c.err})
		err := s.refuseProgramRules(ctx, shared.NewID(), []string{"a.example"})
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("source %v: got %v, want %v", c.err, err, c.want)
		}
	}
	if err := s.refuseProgramRules(ctx, shared.NewID(), nil); err != nil {
		t.Fatalf("no target: %v", err)
	}
}
