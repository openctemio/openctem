package scanrun

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RecentRun is one of a scan's latest runs as the scan list shows it: a dot
// in the run history and one term of the success rate. Only the state and
// when it was created; the run itself opens from the run list.
type RecentRun struct {
	ID          shared.ID
	Status      RunStatus
	RefusalCode string
	CreatedAt   time.Time
}
