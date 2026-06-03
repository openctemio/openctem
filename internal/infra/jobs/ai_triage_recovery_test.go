package jobs

import (
	"testing"

	"github.com/openctemio/api/pkg/logger"
)

// Stop must be safe to call more than once — a second close(stopCh) would
// panic. (Double Stop can happen on overlapping shutdown paths.)
func TestAITriageRecoveryJob_StopIsIdempotent(t *testing.T) {
	j := &AITriageRecoveryJob{
		logger: logger.NewNop(),
		stopCh: make(chan struct{}),
	}

	j.Stop()
	j.Stop() // must not panic
}
