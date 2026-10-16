// Package contentcatalog is the content catalog of an instance: the
// verified content packages it holds, what each organization installed,
// approval requests and the applied signed state.
//
// Design: docs/rfcs/RFC-099-content-packages.md.
package contentcatalog

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/contentpkg"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Errors.
var (
	ErrNotFound         = fmt.Errorf("%w: content package not found", shared.ErrNotFound)
	ErrInstallNotFound  = fmt.Errorf("%w: the package is not installed", shared.ErrNotFound)
	ErrRequestNotFound  = fmt.Errorf("%w: request not found", shared.ErrNotFound)
	ErrAlreadyInstalled = fmt.Errorf("%w: the package is already installed; update or roll it back", shared.ErrConflict)
	ErrPendingRequest   = fmt.Errorf("%w: a request for this package is already pending", shared.ErrConflict)
	ErrRequestDecided   = fmt.Errorf("%w: the request is no longer pending", shared.ErrConflict)
	ErrVersionConflict  = fmt.Errorf("%w: this id and version exist with other contents", shared.ErrConflict)
	ErrStaleImport      = fmt.Errorf("%w: a newer catalog state was applied meanwhile", shared.ErrConflict)
)

// Package is one package version the instance holds.
type Package struct {
	ID shared.ID
	// TenantID nil: the instance catalog; set: an organization's private
	// package.
	TenantID           *shared.ID
	PackageID          string
	Version            string
	Type               contentpkg.Type
	Origin             string
	Title              string
	Manifest           *contentpkg.Manifest
	ManifestRaw        []byte
	ManifestDigest     string
	ArtifactMediaType  string
	ArtifactDigest     string
	ArtifactSize       int64
	Statement          []byte
	PublisherSignature []byte
	PublisherIdentity  string
	PublisherIssuer    string
	PublisherSignedAt  *time.Time
	Tier               string
	ServiceUse         bool
	RevokedAt          *time.Time
	RevokeReason       string
	RevokeSeverity     string
	CreatedBy          *shared.ID
	CreatedAt          time.Time
}

// Revoked reports whether the version is revoked.
func (p *Package) Revoked() bool { return p.RevokedAt != nil }

// InstallStatus is the state of an installation.
type InstallStatus string

// Install statuses.
const (
	InstallActive  InstallStatus = "active"
	InstallRevoked InstallStatus = "revoked"
)

// Install is one package an organization installed.
type Install struct {
	ID                  shared.ID
	TenantID            shared.ID
	PackageID           string
	PackageRowID        shared.ID
	PreviousRowID       *shared.ID
	Pinned              bool
	Status              InstallStatus
	LicenseAcknowledged bool
	InstalledBy         *shared.ID
	UpdatedBy           *shared.ID
	CreatedAt           time.Time
	UpdatedAt           time.Time
	// Package and Previous are the installed and previous versions (read).
	Package  *Package
	Previous *Package
}

// RequestAction is what a request asks for.
type RequestAction string

// Request actions.
const (
	ActionInstall   RequestAction = "install"
	ActionUpdate    RequestAction = "update"
	ActionRollback  RequestAction = "rollback"
	ActionUninstall RequestAction = "uninstall"
)

// RequestStatus is the state of a request.
type RequestStatus string

// Request statuses.
const (
	RequestPending  RequestStatus = "pending"
	RequestApproved RequestStatus = "approved"
	RequestRejected RequestStatus = "rejected"
	RequestCanceled RequestStatus = "canceled"
	RequestFailed   RequestStatus = "failed"
)

// Request is an install, update, rollback or uninstall waiting for a second
// person.
type Request struct {
	ID                  shared.ID
	TenantID            shared.ID
	PackageID           string
	Action              RequestAction
	TargetRowID         *shared.ID
	Pinned              bool
	LicenseAcknowledged bool
	Status              RequestStatus
	Note                string
	DecisionReason      string
	RequestedBy         *shared.ID
	DecidedBy           *shared.ID
	DecidedAt           *time.Time
	CreatedAt           time.Time
	// Target is the requested version (read).
	Target *Package
}

// TrustState is the signed state the instance applied.
type TrustState struct {
	KeySetVersion        uint64
	IndexSequence        uint64
	IndexDigest          string
	IndexExpiresAt       *time.Time
	RevocationsSequence  uint64
	RevocationsDigest    string
	RevocationsIssuedAt  *time.Time
	RevocationsExpiresAt *time.Time
	ImportedAt           *time.Time
}

// RevocationsStale reports whether no revocation list is applied or the
// applied one is past its expiry.
func (t *TrustState) RevocationsStale(now time.Time) bool {
	return t.RevocationsExpiresAt == nil || !t.RevocationsExpiresAt.After(now)
}

// ApprovalOffDelay is how long turning approval off waits before it takes
// effect; turning it on is immediate and cancels a pending switch-off.
const ApprovalOffDelay = 24 * time.Hour

// Settings is an organization's catalog settings.
type Settings struct {
	// RequireApproval is the stored choice; ApprovalOffAt, when set, is
	// when a switch-off takes effect.
	RequireApproval bool
	ApprovalOffAt   *time.Time
	UpdatedBy       *shared.ID
	UpdatedAt       *time.Time
}

// ApprovalRequired reports whether installs need approval at now.
func (s *Settings) ApprovalRequired(now time.Time) bool {
	return s.RequireApproval && (s.ApprovalOffAt == nil || now.Before(*s.ApprovalOffAt))
}

// ImportBatch is a verified bundle to store in one transaction.
type ImportBatch struct {
	KeySetVersion        uint64
	IndexSequence        uint64
	IndexDigest          string
	IndexExpiresAt       time.Time
	RevocationsSequence  uint64
	RevocationsDigest    string
	RevocationsIssuedAt  time.Time
	RevocationsExpiresAt time.Time
	Revocations          []contentpkg.RevocationEntry
	Packages             []*Package
	ImportedAt           time.Time
}

// ImportOutcome is what an import changed.
type ImportOutcome struct {
	Added           int
	Existing        int
	RevokedVersions int
	RevokedInstalls int
}

// Filter narrows a catalog listing.
type Filter struct {
	Type      contentpkg.Type
	Search    string
	Installed *bool
	Limit     int
	Offset    int
}

// Listing is the newest version of one package visible to an organization,
// with its installation.
type Listing struct {
	Latest   *Package
	Versions int
	Install  *Install
}

// Repository stores the catalog. Every method that takes a tenant id reads
// or writes only that organization's rows and the instance catalog.
type Repository interface {
	GetTrust(ctx context.Context) (*TrustState, error)
	ListRevocations(ctx context.Context) ([]contentpkg.RevocationEntry, error)
	// ApplyImport stores a verified bundle in one transaction: it re-checks
	// the applied sequences under a row lock (ErrStaleImport), adds the
	// package versions (ErrVersionConflict for the same id and version with
	// another manifest digest), keeps the revocation entries, revokes the
	// versions they name and the installations of those versions.
	ApplyImport(ctx context.Context, b *ImportBatch) (*ImportOutcome, error)

	ListPackages(ctx context.Context, tenantID shared.ID, f Filter) ([]Listing, int, error)
	ListVersions(ctx context.Context, tenantID shared.ID, packageID string) ([]*Package, error)
	GetVersion(ctx context.Context, tenantID shared.ID, packageID, version string) (*Package, error)
	GetPackageRow(ctx context.Context, tenantID, rowID shared.ID) (*Package, error)

	GetInstall(ctx context.Context, tenantID shared.ID, packageID string) (*Install, error)
	ListInstalls(ctx context.Context, tenantID shared.ID) ([]*Install, error)
	CreateInstall(ctx context.Context, in *Install) error
	UpdateInstall(ctx context.Context, in *Install) error
	DeleteInstall(ctx context.Context, tenantID shared.ID, packageID string) error
	// ListFollowing returns the active, unpinned installations of packageIDs
	// across organizations (the automatic update after an import).
	ListFollowing(ctx context.Context, packageIDs []string) ([]*Install, error)

	CreateRequest(ctx context.Context, r *Request) error
	GetRequest(ctx context.Context, tenantID, id shared.ID) (*Request, error)
	ListRequests(ctx context.Context, tenantID shared.ID, status RequestStatus, limit int) ([]*Request, error)
	// DecideRequest moves a pending request to status (or an approved one
	// to failed, by its approver); ErrRequestDecided otherwise.
	DecideRequest(ctx context.Context, tenantID, id shared.ID, status RequestStatus, decidedBy *shared.ID, reason string, at time.Time) error

	// InTx runs fn with a repository whose statements share one
	// transaction (committed when fn returns nil).
	InTx(ctx context.Context, fn func(Repository) error) error

	// ListAdmins returns the organization's owners and administrators.
	ListAdmins(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)

	GetSettings(ctx context.Context, tenantID shared.ID) (*Settings, error)
	PutSettings(ctx context.Context, tenantID shared.ID, s *Settings) error
}
