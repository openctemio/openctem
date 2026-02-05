package branch

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Branch represents a git branch in a repository.
// Branch belongs to Repository (via RepositoryExtension), not generic Asset.
type Branch struct {
	id                     shared.ID
	repositoryID           shared.ID // Reference to repository (asset_repositories.asset_id)
	name                   string
	branchType             Type
	isDefault              bool
	isProtected            bool
	lastCommitSHA          string
	lastCommitMessage      string
	lastCommitAuthor       string
	lastCommitAuthorAvatar string
	lastCommitAt           *time.Time
	scanOnPush             bool
	scanOnPR               bool
	lastScanID             *shared.ID
	lastScannedAt          *time.Time
	scanStatus             ScanStatus
	qualityGateStatus      QualityGateStatus
	findingsTotal          int
	findingsCritical       int
	findingsHigh           int
	findingsMedium         int
	findingsLow            int
	keepWhenInactive       bool
	retentionDays          *int
	createdAt              time.Time
	updatedAt              time.Time
}

// NewBranch creates a new Branch with required fields.
// repositoryID must reference a valid repository (asset_repositories.asset_id).
func NewBranch(
	repositoryID shared.ID,
	name string,
	branchType Type,
) (*Branch, error) {
	if repositoryID.IsZero() {
		return nil, fmt.Errorf("%w: repository id is required", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if !branchType.IsValid() {
		branchType = TypeOther
	}

	now := time.Now().UTC()
	return &Branch{
		id:                shared.NewID(),
		repositoryID:      repositoryID,
		name:              name,
		branchType:        branchType,
		isDefault:         false,
		isProtected:       false,
		scanOnPush:        true,
		scanOnPR:          true,
		scanStatus:        ScanStatusNotScanned,
		qualityGateStatus: QualityGateNotComputed,
		keepWhenInactive:  true,
		createdAt:         now,
		updatedAt:         now,
	}, nil
}

// Reconstitute recreates a Branch from persistence.
func Reconstitute(
	id shared.ID,
	repositoryID shared.ID,
	name string,
	branchType Type,
	isDefault bool,
	isProtected bool,
	lastCommitSHA string,
	lastCommitMessage string,
	lastCommitAuthor string,
	lastCommitAuthorAvatar string,
	lastCommitAt *time.Time,
	scanOnPush bool,
	scanOnPR bool,
	lastScanID *shared.ID,
	lastScannedAt *time.Time,
	scanStatus ScanStatus,
	qualityGateStatus QualityGateStatus,
	findingsTotal int,
	findingsCritical int,
	findingsHigh int,
	findingsMedium int,
	findingsLow int,
	keepWhenInactive bool,
	retentionDays *int,
	createdAt time.Time,
	updatedAt time.Time,
) *Branch {
	return &Branch{
		id:                     id,
		repositoryID:           repositoryID,
		name:                   name,
		branchType:             branchType,
		isDefault:              isDefault,
		isProtected:            isProtected,
		lastCommitSHA:          lastCommitSHA,
		lastCommitMessage:      lastCommitMessage,
		lastCommitAuthor:       lastCommitAuthor,
		lastCommitAuthorAvatar: lastCommitAuthorAvatar,
		lastCommitAt:           lastCommitAt,
		scanOnPush:             scanOnPush,
		scanOnPR:               scanOnPR,
		lastScanID:             lastScanID,
		lastScannedAt:          lastScannedAt,
		scanStatus:             scanStatus,
		qualityGateStatus:      qualityGateStatus,
		findingsTotal:          findingsTotal,
		findingsCritical:       findingsCritical,
		findingsHigh:           findingsHigh,
		findingsMedium:         findingsMedium,
		findingsLow:            findingsLow,
		keepWhenInactive:       keepWhenInactive,
		retentionDays:          retentionDays,
		createdAt:              createdAt,
		updatedAt:              updatedAt,
	}
}

// Getters

func (b *Branch) ID() shared.ID                        { return b.id }
func (b *Branch) RepositoryID() shared.ID              { return b.repositoryID }
func (b *Branch) Name() string                         { return b.name }
func (b *Branch) Type() Type                           { return b.branchType }
func (b *Branch) IsDefault() bool                      { return b.isDefault }
func (b *Branch) IsProtected() bool                    { return b.isProtected }
func (b *Branch) LastCommitSHA() string                { return b.lastCommitSHA }
func (b *Branch) LastCommitMessage() string            { return b.lastCommitMessage }
func (b *Branch) LastCommitAuthor() string             { return b.lastCommitAuthor }
func (b *Branch) LastCommitAuthorAvatar() string       { return b.lastCommitAuthorAvatar }
func (b *Branch) LastCommitAt() *time.Time             { return b.lastCommitAt }
func (b *Branch) ScanOnPush() bool                     { return b.scanOnPush }
func (b *Branch) ScanOnPR() bool                       { return b.scanOnPR }
func (b *Branch) LastScanID() *shared.ID               { return b.lastScanID }
func (b *Branch) LastScannedAt() *time.Time            { return b.lastScannedAt }
func (b *Branch) ScanStatus() ScanStatus               { return b.scanStatus }
func (b *Branch) QualityGateStatus() QualityGateStatus { return b.qualityGateStatus }
func (b *Branch) FindingsTotal() int                   { return b.findingsTotal }
func (b *Branch) FindingsCritical() int                { return b.findingsCritical }
func (b *Branch) FindingsHigh() int                    { return b.findingsHigh }
func (b *Branch) FindingsMedium() int                  { return b.findingsMedium }
func (b *Branch) FindingsLow() int                     { return b.findingsLow }
func (b *Branch) KeepWhenInactive() bool               { return b.keepWhenInactive }
func (b *Branch) RetentionDays() *int                  { return b.retentionDays }
func (b *Branch) CreatedAt() time.Time                 { return b.createdAt }
func (b *Branch) UpdatedAt() time.Time                 { return b.updatedAt }

// Mutators

func (b *Branch) SetDefault(isDefault bool) {
	b.isDefault = isDefault
	b.updatedAt = time.Now().UTC()
}

func (b *Branch) SetProtected(isProtected bool) {
	b.isProtected = isProtected
	b.updatedAt = time.Now().UTC()
}

func (b *Branch) UpdateLastCommit(sha, message, author, avatar string, at time.Time) {
	b.lastCommitSHA = sha
	b.lastCommitMessage = message
	b.lastCommitAuthor = author
	b.lastCommitAuthorAvatar = avatar
	b.lastCommitAt = &at
	b.updatedAt = time.Now().UTC()
}

func (b *Branch) SetScanConfig(scanOnPush, scanOnPR bool) {
	b.scanOnPush = scanOnPush
	b.scanOnPR = scanOnPR
	b.updatedAt = time.Now().UTC()
}

func (b *Branch) MarkScanned(scanID shared.ID, status ScanStatus, qualityGate QualityGateStatus) {
	b.lastScanID = &scanID
	now := time.Now().UTC()
	b.lastScannedAt = &now
	b.scanStatus = status
	b.qualityGateStatus = qualityGate
	b.updatedAt = now
}

func (b *Branch) UpdateFindingStats(total, critical, high, medium, low int) {
	b.findingsTotal = total
	b.findingsCritical = critical
	b.findingsHigh = high
	b.findingsMedium = medium
	b.findingsLow = low
	b.updatedAt = time.Now().UTC()
}

func (b *Branch) SetRetention(keepWhenInactive bool, days *int) {
	b.keepWhenInactive = keepWhenInactive
	b.retentionDays = days
	b.updatedAt = time.Now().UTC()
}

// Helper methods

func (b *Branch) HasFindings() bool {
	return b.findingsTotal > 0
}

func (b *Branch) HasCriticalFindings() bool {
	return b.findingsCritical > 0
}

func (b *Branch) IsPassing() bool {
	return b.qualityGateStatus == QualityGatePassed
}

func (b *Branch) NeedsScan() bool {
	return b.scanStatus == ScanStatusNotScanned || b.lastScannedAt == nil
}
