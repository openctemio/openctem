package scansession

import (
	"time"

	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ScanSession represents an individual scan execution from an agent.
// Unlike Scan (which is a configuration/definition), ScanSession tracks
// the actual execution lifecycle of a scan.
type ScanSession struct {
	ID       shared.ID
	TenantID shared.ID
	AgentID  *shared.ID

	// Scanner info
	ScannerName    string
	ScannerVersion string
	ScannerType    string // sast, sca, secret, container, etc.

	// Asset info
	AssetType  string // repository, container, host, etc.
	AssetValue string // repo URL, image name, hostname
	AssetID    *shared.ID

	// Git context (for repository scans)
	CommitSha     string
	Branch        string
	BaseCommitSha string // Baseline commit for incremental scan

	// Status
	Status       Status
	ErrorMessage string

	// Results summary
	FindingsTotal      int
	FindingsNew        int
	FindingsFixed      int
	FindingsBySeverity map[string]int

	// Timing
	StartedAt   *time.Time
	CompletedAt *time.Time
	DurationMs  int64

	// Metadata
	Metadata map[string]any

	// Scan Profile and Quality Gate
	ScanProfileID     *shared.ID                     // Reference to the scan profile used
	QualityGateResult *scanprofile.QualityGateResult // Quality gate evaluation result

	// Audit
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Status represents the scan session status.
type Status string

const (
	StatusQueued    Status = "queued"    // Scan is queued, waiting for agent assignment
	StatusPending   Status = "pending"   // Scan is assigned to agent, waiting to start
	StatusRunning   Status = "running"   // Scan is actively running
	StatusCompleted Status = "completed" // Scan completed successfully
	StatusFailed    Status = "failed"    // Scan failed with error
	StatusCanceled  Status = "canceled"  // Scan was manually canceled
	StatusTimeout   Status = "timeout"   // Scan exceeded time limit
)

// AllStatuses returns all valid statuses.
func AllStatuses() []Status {
	return []Status{
		StatusQueued,
		StatusPending,
		StatusRunning,
		StatusCompleted,
		StatusFailed,
		StatusCanceled,
		StatusTimeout,
	}
}

// IsValid checks if the status is a valid status value.
func (s Status) IsValid() bool {
	switch s {
	case StatusQueued, StatusPending, StatusRunning, StatusCompleted, StatusFailed, StatusCanceled, StatusTimeout:
		return true
	}
	return false
}

// IsTerminal returns true if the status is a terminal (final) state.
func (s Status) IsTerminal() bool {
	switch s {
	case StatusCompleted, StatusFailed, StatusCanceled, StatusTimeout:
		return true
	}
	return false
}

// IsActive returns true if the status indicates an active/in-progress state.
func (s Status) IsActive() bool {
	return s == StatusQueued || s == StatusPending || s == StatusRunning
}

// String returns the string representation of the status.
func (s Status) String() string {
	return string(s)
}

// NewScanSession creates a new scan session.
func NewScanSession(tenantID shared.ID, scannerName, assetType, assetValue string) (*ScanSession, error) {
	if scannerName == "" {
		return nil, shared.NewDomainError("VALIDATION", "scanner_name is required", shared.ErrValidation)
	}
	if assetType == "" {
		return nil, shared.NewDomainError("VALIDATION", "asset_type is required", shared.ErrValidation)
	}
	if assetValue == "" {
		return nil, shared.NewDomainError("VALIDATION", "asset_value is required", shared.ErrValidation)
	}

	now := time.Now()
	return &ScanSession{
		ID:                 shared.NewID(),
		TenantID:           tenantID,
		ScannerName:        scannerName,
		AssetType:          assetType,
		AssetValue:         assetValue,
		Status:             StatusPending,
		FindingsBySeverity: make(map[string]int),
		Metadata:           make(map[string]any),
		CreatedAt:          now,
		UpdatedAt:          now,
	}, nil
}

// SetAgent sets the agent executing this scan.
func (s *ScanSession) SetAgent(agentID shared.ID) {
	s.AgentID = &agentID
	s.UpdatedAt = time.Now()
}

// SetScannerInfo sets scanner version and type.
func (s *ScanSession) SetScannerInfo(version, scannerType string) {
	s.ScannerVersion = version
	s.ScannerType = scannerType
	s.UpdatedAt = time.Now()
}

// SetGitContext sets git-related context.
func (s *ScanSession) SetGitContext(commitSha, branch, baseCommitSha string) {
	s.CommitSha = commitSha
	s.Branch = branch
	s.BaseCommitSha = baseCommitSha
	s.UpdatedAt = time.Now()
}

// SetAsset links this session to an asset.
func (s *ScanSession) SetAsset(assetID shared.ID) {
	s.AssetID = &assetID
	s.UpdatedAt = time.Now()
}

// Start marks the scan as running.
func (s *ScanSession) Start() error {
	if s.Status != StatusPending {
		return shared.NewDomainError("INVALID_STATE", "can only start a pending scan", shared.ErrValidation)
	}
	now := time.Now()
	s.Status = StatusRunning
	s.StartedAt = &now
	s.UpdatedAt = now
	return nil
}

// Complete marks the scan as completed.
func (s *ScanSession) Complete(findingsTotal, findingsNew, findingsFixed int, findingsBySeverity map[string]int) error {
	if s.Status != StatusRunning && s.Status != StatusPending {
		return shared.NewDomainError("INVALID_STATE", "can only complete a running or pending scan", shared.ErrValidation)
	}

	now := time.Now()
	s.Status = StatusCompleted
	s.CompletedAt = &now
	s.FindingsTotal = findingsTotal
	s.FindingsNew = findingsNew
	s.FindingsFixed = findingsFixed
	if findingsBySeverity != nil {
		s.FindingsBySeverity = findingsBySeverity
	}
	s.UpdatedAt = now

	// Calculate duration
	if s.StartedAt != nil {
		s.DurationMs = now.Sub(*s.StartedAt).Milliseconds()
	}

	return nil
}

// Fail marks the scan as failed.
func (s *ScanSession) Fail(errorMessage string) error {
	if s.Status != StatusRunning && s.Status != StatusPending {
		return shared.NewDomainError("INVALID_STATE", "can only fail a running or pending scan", shared.ErrValidation)
	}

	now := time.Now()
	s.Status = StatusFailed
	s.CompletedAt = &now
	s.ErrorMessage = errorMessage
	s.UpdatedAt = now

	// Calculate duration
	if s.StartedAt != nil {
		s.DurationMs = now.Sub(*s.StartedAt).Milliseconds()
	}

	return nil
}

// Cancel marks the scan as canceled.
func (s *ScanSession) Cancel() error {
	if s.Status.IsTerminal() {
		return shared.NewDomainError("INVALID_STATE", "cannot cancel a finished scan", shared.ErrValidation)
	}

	now := time.Now()
	s.Status = StatusCanceled
	s.CompletedAt = &now
	s.UpdatedAt = now

	// Calculate duration if started
	if s.StartedAt != nil {
		s.DurationMs = now.Sub(*s.StartedAt).Milliseconds()
	}

	return nil
}

// Timeout marks the scan as timed out.
func (s *ScanSession) Timeout(errorMessage string) error {
	if s.Status.IsTerminal() {
		return shared.NewDomainError("INVALID_STATE", "cannot timeout a finished scan", shared.ErrValidation)
	}

	now := time.Now()
	s.Status = StatusTimeout
	s.CompletedAt = &now
	if errorMessage != "" {
		s.ErrorMessage = errorMessage
	} else {
		s.ErrorMessage = "scan exceeded time limit"
	}
	s.UpdatedAt = now

	// Calculate duration if started
	if s.StartedAt != nil {
		s.DurationMs = now.Sub(*s.StartedAt).Milliseconds()
	}

	return nil
}

// Queue sets the scan to queued status (waiting for agent assignment).
func (s *ScanSession) Queue() error {
	if s.Status != StatusPending {
		return shared.NewDomainError("INVALID_STATE", "can only queue a pending scan", shared.ErrValidation)
	}
	s.Status = StatusQueued
	s.UpdatedAt = time.Now()
	return nil
}

// SetMetadata sets custom metadata.
func (s *ScanSession) SetMetadata(key string, value any) {
	if s.Metadata == nil {
		s.Metadata = make(map[string]any)
	}
	s.Metadata[key] = value
	s.UpdatedAt = time.Now()
}

// IsFinished returns true if the scan has finished (completed, failed, canceled, or timeout).
func (s *ScanSession) IsFinished() bool {
	return s.Status.IsTerminal()
}

// IsRunning returns true if the scan is currently running.
func (s *ScanSession) IsRunning() bool {
	return s.Status == StatusRunning
}

// SetScanProfile links this session to a scan profile.
func (s *ScanSession) SetScanProfile(profileID shared.ID) {
	s.ScanProfileID = &profileID
	s.UpdatedAt = time.Now()
}

// SetQualityGateResult stores the quality gate evaluation result.
func (s *ScanSession) SetQualityGateResult(result *scanprofile.QualityGateResult) {
	s.QualityGateResult = result
	s.UpdatedAt = time.Now()
}

// QualityGatePassed returns true if quality gate passed or was not evaluated.
func (s *ScanSession) QualityGatePassed() bool {
	if s.QualityGateResult == nil {
		return true // No QG = pass
	}
	return s.QualityGateResult.Passed
}
