package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Origin says what produced a record.
// DailyCap is a tenant's evidence budget over a window: at most Limit
// records created since Since. A zero Limit means no cap.
type DailyCap struct {
	Limit int
	Since time.Time
}

// ErrDailyCapReached: the tenant stored its daily evidence budget.
var ErrDailyCapReached = fmt.Errorf("%w: the organization reached its daily evidence limit; try again later", shared.ErrValidation)

type Origin string

const (
	// OriginDetection: a scan report's finding.
	OriginDetection Origin = "detection"
	// OriginRetest: a retest attempt of the finding.
	OriginRetest Origin = "retest"
	// OriginManual: a request/response a person recorded on the finding (a
	// pentest write-up, an import, a drafted finding). Kept with the finding:
	// the age retention does not delete it.
	OriginManual Origin = "manual"
)

// Retention and volume bounds (server-side).
const (
	// MaxDetectionPerFinding: the newest detection records kept per finding
	// (one report may carry MaxItemsPerReport items; a repeated item is not
	// stored again, so this keeps the proof of the last distinct sightings).
	MaxDetectionPerFinding = MaxItemsPerReport
	// MaxRetestPerFinding: the newest retest records kept per finding.
	MaxRetestPerFinding = 20
	// DefaultTenantDailyItems bounds new records per tenant per 24 h.
	DefaultTenantDailyItems = 20000
	// RetentionDays: a record older than this is deleted.
	RetentionDays = 365
	// MaxRevealPlaceholders bounds one reveal request.
	MaxRevealPlaceholders = 50
	// MaxListItems bounds one list response.
	MaxListItems = 25
)

// Errors.
var (
	ErrNotFound = fmt.Errorf("%w: evidence not found", shared.ErrNotFound)
	// ErrSecretsExpired: the item's secret values were deleted (retention).
	ErrSecretsExpired = errors.New("evidence secrets expired")
	// ErrSecretUnreadable: a stored value cannot be opened (wrong key or a
	// value bound to another tenant or item).
	ErrSecretUnreadable = errors.New("evidence secret cannot be decrypted")
	// ErrTooManyManual: the finding would hold more than MaxManualPerFinding
	// recorded request/response items.
	ErrTooManyManual = fmt.Errorf("%w: a finding holds at most %d request/response items", shared.ErrValidation, MaxManualPerFinding)
	// ErrMaskedResent: a request/response holds evidence placeholders (a
	// masked item sent back); its secret values are not in it.
	ErrMaskedResent = fmt.Errorf("%w: a request/response holds masked values; record the original exchange or keep the stored item", shared.ErrValidation)
)

// Role says what an evidence item shows to the reader of a finding.
type Role string

// Evidence roles. A finding's reader sees the baseline (normal behavior),
// the proof (the issue), the verification (the fix check) and anything else
// as supporting.
const (
	RoleBaseline     Role = "baseline"
	RoleProof        Role = "proof"
	RoleVerification Role = "verification"
	RoleSupporting   Role = "supporting"
)

// MaxPosition bounds an item's reader order.
const MaxPosition = 1000

// ParseRole validates a role name.
func ParseRole(s string) (Role, error) {
	switch r := Role(s); r {
	case RoleBaseline, RoleProof, RoleVerification, RoleSupporting:
		return r, nil
	}
	return "", fmt.Errorf("%w: role must be baseline, proof, verification or supporting", shared.ErrValidation)
}

// Record is one stored, masked item.
type Record struct {
	ID             shared.ID
	TenantID       shared.ID
	FindingID      shared.ID
	RetestID       *shared.ID
	Origin         Origin
	Kind           string
	ToolName       string
	RuleID         string
	TemplateDigest string
	Item           Item // masked
	// ContentSHA256 is the platform's sha256 over the normalized item before
	// masking: what the tool sent, within the caps.
	ContentSHA256   string
	SizeBytes       int
	Truncated       bool
	MaskedCount     int
	Placeholders    []string
	SecretsExpireAt *time.Time
	CapturedAt      time.Time
	CreatedAt       time.Time
	// Role and Position are the reader's view of the item: what it shows
	// and where it sits (ascending; equal positions fall back to newest
	// first). A new item is supporting at position 0.
	Role     Role
	Position int
}

// SecretsAvailable reports whether the item's secrets can still be revealed.
func (r *Record) SecretsAvailable(now time.Time) bool {
	return r.MaskedCount > 0 && r.SecretsExpireAt != nil && now.Before(*r.SecretsExpireAt)
}

// State summarizes a finding's evidence for a reader or a write-up.
type State struct {
	// Version counts every change to the finding's evidence.
	Version int64
	// ProofCount is how many records have the proof role.
	ProofCount int
}

// StoredSecret is one encrypted value of a record.
type StoredSecret struct {
	Placeholder string
	Kind        string
	Ciphertext  string
	ExpiresAt   time.Time
}

// NewRecord is what the service hands the repository to store.
type NewRecord struct {
	Record  Record
	Secrets []StoredSecret
}

// Repository persists evidence. Every method is tenant-scoped.
type Repository interface {
	// InsertForFingerprints stores detection records for the findings with
	// the given fingerprints (one record list per fingerprint), skipping a
	// record whose content hash the finding already holds,
	// and prunes each finding to MaxDetectionPerFinding. It returns how many
	// records were stored.
	InsertForFingerprints(ctx context.Context, tenantID shared.ID, byFingerprint map[string][]NewRecord) (int, error)
	// InsertForFinding stores records for one finding (retest attempts) and
	// prunes the finding's retest records to MaxRetestPerFinding.
	InsertForFinding(ctx context.Context, tenantID, findingID shared.ID, recs []NewRecord) error
	// InsertManual stores recorded (manual) records for one finding, skipping
	// a record whose content hash the finding's manual records already hold.
	// More than MaxManualPerFinding manual records is ErrTooManyManual and
	// stores nothing; a finding of another tenant is ErrNotFound. With a cap,
	// the tenant's records since cap.Since are counted inside the insert
	// transaction under a per-tenant lock, and a write that would pass
	// cap.Limit is ErrDailyCapReached and stores nothing (so concurrent writes
	// cannot exceed it). It returns how many records were stored.
	InsertManual(ctx context.Context, tenantID, findingID shared.ID, recs []NewRecord, cap DailyCap) (int, error)
	// MoveLegacyRequestResponses moves request/response entries still kept in
	// findings.metadata (key request_responses, written before they went
	// through the evidence service) into manual records: it locks up to batch
	// such findings, lets convert build the masked records, stores them and
	// removes the key, in one transaction per batch and one savepoint per
	// finding (a finding that fails is skipped, not retried in the run).
	// after is the last id of the previous batch ("" = from the start); an
	// empty result (Moved+Skipped == 0) means none is left.
	MoveLegacyRequestResponses(ctx context.Context, batch int, after string, convert LegacyConverter) (LegacyMoveResult, error)
	// List returns a finding's records in reader order (position, then
	// newest first); retestID filters to one retest attempt.
	List(ctx context.Context, tenantID, findingID shared.ID, retestID *shared.ID, limit int) ([]*Record, error)
	// Get returns one record of a finding.
	Get(ctx context.Context, tenantID, findingID, id shared.ID) (*Record, error)
	// Update sets the role and/or position of one record of a finding and
	// returns it; a record of another finding or tenant is ErrNotFound.
	Update(ctx context.Context, tenantID, findingID, id shared.ID, role *Role, position *int) (*Record, error)
	// SetOrder gives the listed records the positions 0..n-1 in the order of
	// ids and the finding's other records position n. Every id must be a
	// record of the finding (else ErrNotFound).
	SetOrder(ctx context.Context, tenantID, findingID shared.ID, ids []shared.ID) error
	// State returns the finding's evidence version and how many records
	// have the proof role.
	State(ctx context.Context, tenantID, findingID shared.ID) (State, error)
	// FindingSource returns the finding's source ("pentest", "sast", ...);
	// a finding of another tenant is ErrNotFound.
	FindingSource(ctx context.Context, tenantID, findingID shared.ID) (string, error)
	// Secrets returns the stored secrets of a record for the placeholders.
	Secrets(ctx context.Context, tenantID, evidenceID shared.ID, placeholders []string) ([]StoredSecret, error)
	// CountSince counts a tenant's records created since t.
	CountSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error)
	// DeleteExpired deletes expired secrets and records older than the
	// retention. It returns how many of each were deleted.
	DeleteExpired(ctx context.Context, now time.Time, retention time.Duration) (secrets, records int64, err error)
}

// LegacyMoveResult is one batch of the legacy request/response move.
type LegacyMoveResult struct {
	Moved   int    // findings moved
	Skipped int    // findings that failed and were left as they were
	Last    string // id of the last finding looked at (the next cursor)
}

// LegacyConverter turns a finding's legacy request/response entries into
// masked records ready to store.
type LegacyConverter func(ctx context.Context, tenantID, findingID shared.ID, entries []map[string]any) []NewRecord

// Hash is the platform's content hash of a normalized item.
func Hash(it Item) string {
	b, err := json.Marshal(it)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SecretAAD binds a secret's plaintext to its tenant, record and placeholder:
// the stored plaintext is this prefix plus the value, and a value is only
// returned when the prefix matches, so a ciphertext copied to another row,
// record or tenant does not open.
func SecretAAD(tenantID, evidenceID shared.ID, placeholder string) string {
	return "evidence:v1|" + tenantID.String() + "|" + evidenceID.String() + "|" + placeholder + "|"
}
