package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/scansession"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ScanSessionService handles scan session lifecycle management.
type ScanSessionService struct {
	sessionRepo scansession.Repository
	agentRepo   agent.Repository
	logger      *logger.Logger
}

// NewScanSessionService creates a new ScanSessionService.
func NewScanSessionService(
	sessionRepo scansession.Repository,
	agentRepo agent.Repository,
	log *logger.Logger,
) *ScanSessionService {
	return &ScanSessionService{
		sessionRepo: sessionRepo,
		agentRepo:   agentRepo,
		logger:      log.With("service", "scan_session"),
	}
}

// RegisterScanInput represents the input to register a new scan.
type RegisterScanInput struct {
	ScannerName    string `json:"scanner_name" validate:"required"`
	ScannerVersion string `json:"scanner_version"`
	ScannerType    string `json:"scanner_type"`
	AssetType      string `json:"asset_type" validate:"required"`
	AssetValue     string `json:"asset_value" validate:"required"`
	CommitSha      string `json:"commit_sha"`
	Branch         string `json:"branch"`
}

// RegisterScanOutput represents the output from registering a scan.
type RegisterScanOutput struct {
	ScanID        string `json:"scan_id"`
	BaseCommitSha string `json:"base_commit_sha"` // For incremental scanning
	ScanURL       string `json:"scan_url"`
}

// RegisterScan registers a new scan session and returns baseline info.
func (s *ScanSessionService) RegisterScan(ctx context.Context, agt *agent.Agent, input RegisterScanInput) (*RegisterScanOutput, error) {
	// Platform agents must have tenant context from job assignment
	if agt.TenantID == nil {
		return nil, fmt.Errorf("agent has no tenant context: platform agents require job assignment")
	}
	tenantID := *agt.TenantID

	// Create scan session
	session, err := scansession.NewScanSession(tenantID, input.ScannerName, input.AssetType, input.AssetValue)
	if err != nil {
		return nil, err
	}

	session.SetAgent(agt.ID)
	session.SetScannerInfo(input.ScannerVersion, input.ScannerType)
	session.SetGitContext(input.CommitSha, input.Branch, "")

	// Start the scan immediately
	if err := session.Start(); err != nil {
		return nil, err
	}

	// Find baseline commit for incremental scanning
	baseCommitSha, err := s.sessionRepo.FindBaseline(ctx, tenantID, input.AssetType, input.AssetValue, input.Branch)
	if err != nil {
		s.logger.Warn("failed to find baseline", "error", err)
		// Don't fail - just proceed without baseline
	}

	if baseCommitSha != "" {
		session.SetGitContext(input.CommitSha, input.Branch, baseCommitSha)
	}

	// Save session
	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	s.logger.Info("scan registered",
		"scan_id", session.ID.String(),
		"scanner", input.ScannerName,
		"asset", input.AssetValue,
		"branch", input.Branch,
		"baseline", baseCommitSha,
	)

	return &RegisterScanOutput{
		ScanID:        session.ID.String(),
		BaseCommitSha: baseCommitSha,
		// ScanURL: constructed by handler based on config
	}, nil
}

// UpdateScanSessionInput represents the input to update scan session status.
type UpdateScanSessionInput struct {
	Status             string         `json:"status" validate:"required,oneof=completed failed canceled"`
	ErrorMessage       string         `json:"error_message"`
	FindingsTotal      int            `json:"findings_total"`
	FindingsNew        int            `json:"findings_new"`
	FindingsFixed      int            `json:"findings_fixed"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
}

// UpdateScanSession updates a scan session status.
func (s *ScanSessionService) UpdateScanSession(ctx context.Context, agt *agent.Agent, scanID string, input UpdateScanSessionInput) error {
	// Platform agents must have tenant context from job assignment
	if agt.TenantID == nil {
		return fmt.Errorf("agent has no tenant context: platform agents require job assignment")
	}
	tenantID := *agt.TenantID

	id, err := shared.IDFromString(scanID)
	if err != nil {
		return shared.NewDomainError("VALIDATION", "invalid scan_id", shared.ErrValidation)
	}

	session, err := s.sessionRepo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		return err
	}

	// Verify agent owns this session
	if session.AgentID != nil && !session.AgentID.Equals(agt.ID) {
		return shared.NewDomainError("FORBIDDEN", "scan session belongs to different agent", shared.ErrForbidden)
	}

	switch input.Status {
	case "completed":
		err = session.Complete(input.FindingsTotal, input.FindingsNew, input.FindingsFixed, input.FindingsBySeverity)
	case "failed":
		err = session.Fail(input.ErrorMessage)
	case "canceled":
		err = session.Cancel()
	default:
		err = shared.NewDomainError("VALIDATION", "invalid status", shared.ErrValidation)
	}

	if err != nil {
		return err
	}

	if err := s.sessionRepo.Update(ctx, session); err != nil {
		return err
	}

	s.logger.Info("scan updated",
		"scan_id", scanID,
		"status", input.Status,
		"findings", input.FindingsTotal,
	)

	return nil
}

// GetScan retrieves a scan session by ID.
func (s *ScanSessionService) GetScan(ctx context.Context, tenantID shared.ID, scanID string) (*scansession.ScanSession, error) {
	id, err := shared.IDFromString(scanID)
	if err != nil {
		return nil, shared.NewDomainError("VALIDATION", "invalid scan_id", shared.ErrValidation)
	}

	return s.sessionRepo.GetByTenantAndID(ctx, tenantID, id)
}

// ListScanSessionsInput represents the input for listing scan sessions.
type ListScanSessionsInput struct {
	ScannerName string
	AssetType   string
	AssetValue  string
	Branch      string
	Status      string
	Since       *time.Time
	Until       *time.Time
}

// ListScanSessions lists scan sessions for a tenant.
func (s *ScanSessionService) ListScanSessions(ctx context.Context, tenantID shared.ID, input ListScanSessionsInput, page pagination.Pagination) (pagination.Result[*scansession.ScanSession], error) {
	filter := scansession.Filter{
		TenantID:    &tenantID,
		ScannerName: input.ScannerName,
		AssetType:   input.AssetType,
		AssetValue:  input.AssetValue,
		Branch:      input.Branch,
		Since:       input.Since,
		Until:       input.Until,
	}

	if input.Status != "" {
		status := scansession.Status(input.Status)
		filter.Status = &status
	}

	return s.sessionRepo.List(ctx, filter, page)
}

// GetStats retrieves scan session statistics.
func (s *ScanSessionService) GetStats(ctx context.Context, tenantID shared.ID, since time.Time) (*scansession.Stats, error) {
	return s.sessionRepo.GetStats(ctx, tenantID, since)
}

// ListRunning lists all currently running scans for a tenant.
func (s *ScanSessionService) ListRunning(ctx context.Context, tenantID shared.ID) ([]*scansession.ScanSession, error) {
	return s.sessionRepo.ListRunning(ctx, tenantID)
}

// DeleteScan deletes a scan session.
func (s *ScanSessionService) DeleteScan(ctx context.Context, tenantID shared.ID, scanID string) error {
	id, err := shared.IDFromString(scanID)
	if err != nil {
		return shared.NewDomainError("VALIDATION", "invalid scan_id", shared.ErrValidation)
	}

	// Verify tenant owns this session
	_, err = s.sessionRepo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		return err
	}

	return s.sessionRepo.Delete(ctx, id)
}
