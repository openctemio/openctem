package threatintel

import (
	"errors"
	"fmt"
)

// Domain errors for threat intelligence.
var (
	// ErrEPSSNotFound is returned when an EPSS score is not found.
	ErrEPSSNotFound = errors.New("epss score not found")

	// ErrKEVNotFound is returned when a KEV entry is not found.
	ErrKEVNotFound = errors.New("kev entry not found")

	// ErrSyncStatusNotFound is returned when a sync status is not found.
	ErrSyncStatusNotFound = errors.New("sync status not found")

	// ErrSyncAlreadyRunning is returned when a sync is already in progress.
	ErrSyncAlreadyRunning = errors.New("sync already running")

	// ErrSyncDisabled is returned when sync is disabled for a source.
	ErrSyncDisabled = errors.New("sync is disabled for this source")

	// ErrInvalidCVEID is returned when CVE ID format is invalid.
	ErrInvalidCVEID = errors.New("invalid CVE ID format")

	// ErrFetchFailed is returned when fetching threat intel data fails.
	ErrFetchFailed = errors.New("failed to fetch threat intel data")

	// ErrParseFailed is returned when parsing threat intel data fails.
	ErrParseFailed = errors.New("failed to parse threat intel data")
)

// SyncError wraps a sync error with additional context.
type SyncError struct {
	Source  string
	Cause   error
	Message string
}

// NewSyncError creates a new sync error.
func NewSyncError(source string, cause error, message string) *SyncError {
	return &SyncError{
		Source:  source,
		Cause:   cause,
		Message: message,
	}
}

// Error returns the error message.
func (e *SyncError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s sync error: %s: %v", e.Source, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s sync error: %s", e.Source, e.Message)
}

// Unwrap returns the underlying error.
func (e *SyncError) Unwrap() error {
	return e.Cause
}
