// Package aimaskmap keeps, per AI run, the masking key and the placeholder
// map the platform needs to turn a model's output back into real values.
// Both are encrypted with the application key before they reach the
// database, expire after a TTL and never leave the platform. Secrets are not
// in the map (pkg/aimask never records them).
//
// Design: docs/architecture/ai-context-masking.md.
package aimaskmap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/aimask"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DefaultTTL is how long a run's map is kept when AI_MASK_MAP_TTL is unset.
const DefaultTTL = 7 * 24 * time.Hour

// ErrNotFound: no map for the run (never stored, expired, or another
// organization's run).
var ErrNotFound = fmt.Errorf("%w: AI mask map", shared.ErrNotFound)

// Row is the stored, encrypted form.
type Row struct {
	TenantID  shared.ID
	RunID     shared.ID
	KeyEnc    string
	MapEnc    string
	ExpiresAt time.Time
}

// Repository stores rows; every query is scoped by tenant.
type Repository interface {
	// Put writes the run's row; a second write for the same run fails
	// (one map per run).
	Put(ctx context.Context, r Row) error
	// Get returns the run's row unless it has expired.
	Get(ctx context.Context, tenantID, runID shared.ID, now time.Time) (Row, error)
	// DeleteExpired removes rows expired before now, at most limit.
	DeleteExpired(ctx context.Context, now time.Time, limit int) (int64, error)
}

// Store encrypts and decrypts run maps.
type Store struct {
	repo Repository
	enc  crypto.Encryptor
	ttl  time.Duration
	now  func() time.Time
}

// NewStore builds the store. ttl <= 0 uses DefaultTTL.
func NewStore(repo Repository, enc crypto.Encryptor, ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Store{repo: repo, enc: enc, ttl: ttl, now: time.Now}
}

// Save stores the run's key and snapshot, encrypted.
func (s *Store) Save(ctx context.Context, tenantID, runID shared.ID, runKey []byte, snap aimask.Snapshot) error {
	if s == nil || s.repo == nil || s.enc == nil {
		return errors.New("aimaskmap: store not configured")
	}
	if len(runKey) != aimask.KeySize {
		return aimask.ErrKey
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("encode mask map: %w", err)
	}
	keyEnc, err := s.enc.EncryptString(base64.StdEncoding.EncodeToString(runKey))
	if err != nil {
		return fmt.Errorf("encrypt mask key: %w", err)
	}
	mapEnc, err := s.enc.EncryptString(string(raw))
	if err != nil {
		return fmt.Errorf("encrypt mask map: %w", err)
	}
	now := s.now().UTC()
	return s.repo.Put(ctx, Row{TenantID: tenantID, RunID: runID, KeyEnc: keyEnc, MapEnc: mapEnc, ExpiresAt: now.Add(s.ttl)})
}

// Load returns the run's key and snapshot. Only the platform's result path
// calls it; it is scoped by the run's tenant.
func (s *Store) Load(ctx context.Context, tenantID, runID shared.ID) ([]byte, aimask.Snapshot, error) {
	if s == nil || s.repo == nil || s.enc == nil {
		return nil, aimask.Snapshot{}, errors.New("aimaskmap: store not configured")
	}
	row, err := s.repo.Get(ctx, tenantID, runID, s.now().UTC())
	if err != nil {
		return nil, aimask.Snapshot{}, err
	}
	keyB64, err := s.enc.DecryptString(row.KeyEnc)
	if err != nil {
		return nil, aimask.Snapshot{}, fmt.Errorf("decrypt mask key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != aimask.KeySize {
		return nil, aimask.Snapshot{}, errors.New("aimaskmap: stored key is malformed")
	}
	raw, err := s.enc.DecryptString(row.MapEnc)
	if err != nil {
		return nil, aimask.Snapshot{}, fmt.Errorf("decrypt mask map: %w", err)
	}
	var snap aimask.Snapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return nil, aimask.Snapshot{}, fmt.Errorf("decode mask map: %w", err)
	}
	return key, snap, nil
}

// Purge deletes expired maps in batches; the retention job calls it.
func (s *Store) Purge(ctx context.Context) (int64, error) {
	if s == nil || s.repo == nil {
		return 0, nil
	}
	var total int64
	for i := 0; i < 100; i++ {
		n, err := s.repo.DeleteExpired(ctx, s.now().UTC(), 1000)
		total += n
		if err != nil || n < 1000 {
			return total, err
		}
	}
	return total, nil
}
