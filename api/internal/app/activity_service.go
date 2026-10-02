package app

// Compatibility shim — real impl lives in internal/app/activity/.
// Activity is its own package (rather than a file under finding/)
// because the finding cluster has cross-dependencies on notification,
// asset, etc. that aren't extracted yet; activity is self-contained
// so it ships first.

import "github.com/openctemio/api/internal/app/activity"

type (
	FindingActivityService = activity.FindingActivityService
	ActivityBroadcaster    = activity.ActivityBroadcaster
	ListActivitiesInput    = activity.ListActivitiesInput
	RecordActivityInput    = activity.RecordActivityInput
)

var (
	NewFindingActivityService = activity.NewFindingActivityService
)

// MaxChangesSize is re-exported so test files using app.MaxChangesSize
// continue to compile.
const MaxChangesSize = activity.MaxChangesSize
