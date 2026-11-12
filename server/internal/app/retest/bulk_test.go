package retest

import (
	"errors"
	"fmt"
	"testing"

	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestBulkOutcome(t *testing.T) {
	for err, want := range map[error]string{
		nil:                   BulkQueued,
		retestdom.ErrInFlight: BulkInFlight,
		fmt.Errorf("%w: cooldown", retestdom.ErrRateLimited): BulkRateLimited,
		retestdom.ErrNoSensor:                                BulkNoSensor,
		retestdom.ErrNotEligible:                             BulkNotEligible,
		shared.ErrNotFound:                                   BulkNotFound,
		errors.New("boom"):                                   BulkFailed,
	} {
		if got := bulkOutcome(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
}
