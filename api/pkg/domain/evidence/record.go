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
type Origin string

const (
	// OriginDetection: a scan report's finding.
	OriginDetection Origin = "detection"
	// OriginRetest: a retest attempt of the finding.
	OriginRetest Origin = "retest"
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
)

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
}

// SecretsAvailable reports whether the item's secrets can still be revealed.
func (r *Record) SecretsAvailable(now time.Time) bool {
	return r.MaskedCount > 0 && r.SecretsExpireAt != nil && now.Before(*r.SecretsExpireAt)
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
	// List returns a finding's records, newest first; retestID filters to
	// one retest attempt.
	List(ctx context.Context, tenantID, findingID shared.ID, retestID *shared.ID, limit int) ([]*Record, error)
	// Get returns one record of a finding.
	Get(ctx context.Context, tenantID, findingID, id shared.ID) (*Record, error)
	// Secrets returns the stored secrets of a record for the placeholders.
	Secrets(ctx context.Context, tenantID, evidenceID shared.ID, placeholders []string) ([]StoredSecret, error)
	// CountSince counts a tenant's records created since t.
	CountSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error)
	// DeleteExpired deletes expired secrets and records older than the
	// retention. It returns how many of each were deleted.
	DeleteExpired(ctx context.Context, now time.Time, retention time.Duration) (secrets, records int64, err error)
}

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
