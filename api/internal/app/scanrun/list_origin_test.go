package scanrun

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestListRuns_RejectsUnknownOrigin(t *testing.T) {
	s := &Service{}
	_, err := s.ListRuns(context.Background(), ListRunsInput{TenantID: shared.NewID().String(), Origin: "bogus"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want a validation error", err)
	}
}
