// Package ingestpayload stores the raw reports of queued CI results and file
// imports until the ingest worker applies them
// (docs/rfcs/RFC-122-ingest-receipts.md, "Accept fast, apply async"). The
// same Sealer seals the queued segments of protocol v2 sensor reports, which
// stay in their ingest_jobs row (docs/rfcs/RFC-026-sensor-results-ingest.md).
//
// A raw report is stored before secrets are masked (masking happens when it
// is applied), so it is sealed at rest: gzip-compressed, then encrypted with
// AES-256-GCM under a key derived per tenant from APP_ENCRYPTION_KEY (HKDF,
// the tenant id in the info string). The additional data binds the
// ciphertext to its tenant, job and part, so a row copied to another tenant
// or job does not open. Rows are deleted once the job is applied and kept
// until ExpiresAt when it failed.
package ingestpayload

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Limits.
const (
	// MaxPartBytes bounds one stored part (the plaintext): the largest body
	// a route accepts (128 MiB decompressed CI results; an import part is
	// smaller).
	MaxPartBytes = 128 << 20
	// MaxParts bounds the parts of one job.
	MaxParts = 64
	// FailedRetention is how long the parts of a job that failed for good
	// are kept for diagnosis before the janitor deletes them.
	FailedRetention = 7 * 24 * time.Hour
)

// Errors.
var (
	// ErrNoKey: the sealer has no key; nothing is stored in plaintext.
	ErrNoKey = errors.New("ingest payload: no encryption key")
	// ErrTooLarge: a part over MaxPartBytes.
	ErrTooLarge = errors.New("ingest payload: part too large")
	// ErrOpen: a part that does not open (wrong key, tenant, job or part,
	// tampered bytes, or a digest mismatch).
	ErrOpen = errors.New("ingest payload: part does not open")
)

// Part is one stored part of a job's raw report, sealed.
type Part struct {
	JobID     shared.ID
	Part      int
	TenantID  shared.ID
	Name      string
	KeyID     string
	SizeBytes int64
	Digest    []byte
	Sealed    []byte
	ExpiresAt time.Time
	// Binding is extra context the caller rebuilds from where the part is
	// stored (not persisted with the part): when set it is part of the
	// additional data, so the part opens only for the same binding. A
	// queued sensor segment binds its report, segment number and content
	// hash (SensorSegmentBinding).
	Binding string
}

// Repository stores sealed parts. Every method is scoped by tenant.
type Repository interface {
	// Put stores one part (replacing a part with the same job and number).
	Put(ctx context.Context, p *Part) error
	// List returns the parts of a job of the tenant, by part number.
	List(ctx context.Context, tenantID, jobID shared.ID) ([]*Part, error)
	// DeleteJob removes a job's parts.
	DeleteJob(ctx context.Context, tenantID, jobID shared.ID) error
}

// Sealer seals and opens parts. The zero value refuses everything.
type Sealer struct {
	current  sealKey
	previous []sealKey
}

type sealKey struct {
	id     string
	master []byte
}

// NewSealer builds a sealer over the current master key (32 bytes, as
// APP_ENCRYPTION_KEY decodes) and any previous ones (key rotation: parts
// sealed under them still open).
func NewSealer(current []byte, previous ...[]byte) (*Sealer, error) {
	if len(current) != 32 {
		return nil, fmt.Errorf("%w: the master key must be 32 bytes", ErrNoKey)
	}
	s := &Sealer{current: newSealKey(current)}
	for _, p := range previous {
		if len(p) != 32 {
			return nil, fmt.Errorf("%w: a previous master key must be 32 bytes", ErrNoKey)
		}
		s.previous = append(s.previous, newSealKey(p))
	}
	return s, nil
}

func newSealKey(master []byte) sealKey {
	sum := sha256.Sum256(append([]byte("openctem/ingest-payload/key-id\x00"), master...))
	return sealKey{id: hex.EncodeToString(sum[:8]), master: append([]byte(nil), master...)}
}

// tenantAEAD derives the tenant's key from the master key.
func (k sealKey) tenantAEAD(tenantID shared.ID) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, k.master, nil, "openctem/ingest-payload/v1/"+tenantID.String(), 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds a part to its tenant, job and number, and to the caller's
// binding when there is one (a part sealed without one keeps the original
// form, so parts stored before bindings existed still open).
func aad(tenantID, jobID shared.ID, part int, binding string) []byte {
	if binding == "" {
		return fmt.Appendf(nil, "%s/%s/%d", tenantID, jobID, part)
	}
	return fmt.Appendf(nil, "%s/%s/%d/%s", tenantID, jobID, part, binding)
}

// SensorSegmentBinding is the binding of one queued protocol v2 sensor
// segment: its report (the ingest_reports row), its segment number and the
// SHA-256 of its decoded bytes. A sealed segment moved to another report,
// segment number or job, or paired with another content hash, does not open.
func SensorSegmentBinding(reportRef shared.ID, seq int, sha256Sum []byte) string {
	return fmt.Sprintf("sensor-v2/%s/%d/%s", reportRef, seq, hex.EncodeToString(sha256Sum))
}

// SensorJobBinding is the binding of one queued protocol v1 sensor job: the
// SHA-256 of its decoded report. A sealed job paired with another content
// hash does not open (the tenant and job id are already in the additional
// data).
func SensorJobBinding(sha256Sum []byte) string {
	return "sensor-v1/" + hex.EncodeToString(sha256Sum)
}

// Seal compresses and encrypts plaintext as part number part of the job.
func (s *Sealer) Seal(tenantID, jobID shared.ID, part int, name string, plaintext []byte) (*Part, error) {
	return s.SealBound(tenantID, jobID, part, name, "", plaintext)
}

// SealBound is Seal with a binding (see Part.Binding); Open needs the same
// binding on the part.
func (s *Sealer) SealBound(tenantID, jobID shared.ID, part int, name, binding string, plaintext []byte) (*Part, error) {
	if s == nil || s.current.master == nil {
		return nil, ErrNoKey
	}
	if len(plaintext) > MaxPartBytes {
		return nil, ErrTooLarge
	}
	if part < 0 || part >= MaxParts {
		return nil, fmt.Errorf("%w: part %d out of range", shared.ErrValidation, part)
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(plaintext); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	aead, err := s.current.tenantAEAD(tenantID)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+buf.Len()+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nonce, nonce, buf.Bytes(), aad(tenantID, jobID, part, binding))
	sum := sha256.Sum256(plaintext)
	return &Part{
		JobID: jobID, Part: part, TenantID: tenantID, Name: name, KeyID: s.current.id,
		SizeBytes: int64(len(plaintext)), Digest: sum[:], Sealed: sealed, Binding: binding,
	}, nil
}

// Open decrypts and decompresses a part, checking its tenant, job, number,
// binding, size and digest.
func (s *Sealer) Open(p *Part) ([]byte, error) {
	if s == nil || s.current.master == nil {
		return nil, ErrNoKey
	}
	if p == nil || p.SizeBytes < 0 || p.SizeBytes > MaxPartBytes {
		return nil, ErrOpen
	}
	key, ok := s.keyFor(p.KeyID)
	if !ok {
		return nil, ErrOpen
	}
	aead, err := key.tenantAEAD(p.TenantID)
	if err != nil {
		return nil, err
	}
	if len(p.Sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrOpen
	}
	nonce, body := p.Sealed[:aead.NonceSize()], p.Sealed[aead.NonceSize():]
	compressed, err := aead.Open(nil, nonce, body, aad(p.TenantID, p.JobID, p.Part, p.Binding))
	if err != nil {
		return nil, ErrOpen
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, ErrOpen
	}
	// Read at most the recorded size plus one byte: a part that expands
	// beyond what was sealed is refused, never read without bound.
	plain, err := io.ReadAll(io.LimitReader(zr, p.SizeBytes+1))
	if err != nil || int64(len(plain)) != p.SizeBytes {
		return nil, ErrOpen
	}
	sum := sha256.Sum256(plain)
	if subtle.ConstantTimeCompare(sum[:], p.Digest) != 1 {
		return nil, ErrOpen
	}
	return plain, nil
}

func (s *Sealer) keyFor(id string) (sealKey, bool) {
	if s.current.id == id {
		return s.current, true
	}
	for _, k := range s.previous {
		if k.id == id {
			return k, true
		}
	}
	return sealKey{}, false
}
