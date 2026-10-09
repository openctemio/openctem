package scope

// Authorization letters (RFC-065 §13): upload, list, read the file, revoke.
// A letter authorizes nothing by itself; the scope entries that name it do,
// through the organization's approval policy, and only while it is valid.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// LetterFileStore keeps a letter's file (the attachment storage).
type LetterFileStore interface {
	Store(ctx context.Context, tenantID, uploadedBy shared.ID, filename, contentType string, size int64, r io.Reader) (shared.ID, error)
	Open(ctx context.Context, tenantID, attachmentID shared.ID) (io.ReadCloser, string, string, error)
}

// SetLetters wires the letters an authorization_letter entry names. Without
// them such an entry is refused (fail closed).
func (s *Service) SetLetters(r scopedom.LetterRepository) { s.letters = r }

// letterRef checks the letter a new letter entry names: the tenant's, and
// valid now.
func (s *Service) letterRef(ctx context.Context, tenantID shared.ID, letterID string) (*shared.ID, error) {
	if strings.TrimSpace(letterID) == "" {
		return nil, scopedom.ErrLetterRequired
	}
	id, err := shared.IDFromString(letterID)
	if err != nil {
		return nil, scopedom.ErrLetterNotFound
	}
	if s.letters == nil {
		return nil, scopedom.ErrLetterNotValid
	}
	l, err := s.letters.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if !l.InEffect(time.Now()) {
		return nil, scopedom.ErrLetterNotValid
	}
	return &id, nil
}

// LetterService manages authorization letters.
type LetterService struct {
	repo scopedom.LetterRepository
	// ledger feeds the job signer's scope ledger (*Service.CommitEntries,
	// RFC-040 §11.5); nil: none.
	ledger LetterLedger
	files  LetterFileStore
	notify func(ctx context.Context, tenantID shared.ID, title, body string)
	now    func() time.Time
}

// NewLetterService wires the service. notify tells every administrator
// (nil: nobody).
func NewLetterService(repo scopedom.LetterRepository, files LetterFileStore, notify func(ctx context.Context, tenantID shared.ID, title, body string)) *LetterService {
	return &LetterService{repo: repo, files: files, notify: notify, now: func() time.Time { return time.Now().UTC() }}
}

// LetterLedger is the job signer's scope ledger hook (*Service.CommitEntries).
type LetterLedger interface {
	CommitEntries(ctx context.Context, tenantID shared.ID, requester string, put []*scopedom.Target,
		removed []shared.ID, platformPolicy string, save func() error) error
}

// SetLedger makes a revocation take the letter's entries out of the job
// signer's ledger too.
func (ls *LetterService) SetLedger(l LetterLedger) { ls.ledger = l }

// UploadLetterInput is a new letter and its file.
type UploadLetterInput struct {
	TenantID    shared.ID
	UploadedBy  shared.ID
	Title       string
	Issuer      string
	Reference   string
	ValidFrom   time.Time // zero: now
	ValidUntil  time.Time
	Filename    string
	ContentType string
	Size        int64
	File        io.Reader
}

// MaxLetterFileSize bounds a letter's file.
const MaxLetterFileSize = 10 << 20 // the attachment storage limit

// Upload stores the file and the letter. The file's SHA-256 is recorded so
// the letter a run relied on can be proven later.
func (ls *LetterService) Upload(ctx context.Context, in UploadLetterInput) (*scopedom.Letter, error) {
	if ls == nil || ls.repo == nil || ls.files == nil {
		return nil, fmt.Errorf("authorization letters are not configured")
	}
	now := ls.now()
	from := in.ValidFrom
	if from.IsZero() {
		from = now
	}
	if err := scopedom.ValidateLetterDetails(in.Title, in.Issuer, in.Reference, from, in.ValidUntil, now); err != nil {
		return nil, err
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(in.ContentType, ";")[0]))
	if !scopedom.LetterContentTypes[ct] {
		return nil, scopedom.ErrLetterFileType
	}
	if in.Size <= 0 || in.Size > MaxLetterFileSize || in.File == nil {
		return nil, fmt.Errorf("%w: the letter file is required (at most %d MB)", shared.ErrValidation, MaxLetterFileSize>>20)
	}
	h := sha256.New()
	attachmentID, err := ls.files.Store(ctx, in.TenantID, in.UploadedBy, in.Filename, ct, in.Size,
		io.TeeReader(io.LimitReader(in.File, MaxLetterFileSize), h))
	if err != nil {
		return nil, fmt.Errorf("store the letter file: %w", err)
	}
	by := in.UploadedBy
	l := &scopedom.Letter{
		ID: shared.NewID(), TenantID: in.TenantID, Title: strings.TrimSpace(in.Title),
		Issuer: strings.TrimSpace(in.Issuer), Reference: strings.TrimSpace(in.Reference),
		ValidFrom: from.UTC(), ValidUntil: in.ValidUntil.UTC(), AttachmentID: attachmentID,
		FileSHA256: hex.EncodeToString(h.Sum(nil)), UploadedBy: &by, CreatedAt: now,
	}
	if err := ls.repo.Create(ctx, l); err != nil {
		return nil, err
	}
	return l, nil
}

// List lists the tenant's letters.
func (ls *LetterService) List(ctx context.Context, tenantID shared.ID) ([]*scopedom.Letter, error) {
	return ls.repo.List(ctx, tenantID)
}

// Get returns one letter of the tenant.
func (ls *LetterService) Get(ctx context.Context, tenantID, id shared.ID) (*scopedom.Letter, error) {
	return ls.repo.GetByID(ctx, tenantID, id)
}

// File opens a letter's file.
func (ls *LetterService) File(ctx context.Context, tenantID, id shared.ID) (io.ReadCloser, string, string, *scopedom.Letter, error) {
	l, err := ls.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, "", "", nil, err
	}
	rc, contentType, filename, err := ls.files.Open(ctx, tenantID, l.AttachmentID)
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("open the letter file: %w", err)
	}
	return rc, contentType, filename, l, nil
}

// Revoke revokes a letter: every entry naming it stops authorizing at once
// (the in-effect read joins the letter). Administrators are told.
func (ls *LetterService) Revoke(ctx context.Context, tenantID, id, by shared.ID) (*scopedom.Letter, error) {
	entries, err := ls.repo.EntryIDs(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	revoke := func() error { return ls.repo.Revoke(ctx, tenantID, id, by, ls.now()) }
	if ls.ledger == nil {
		err = revoke()
	} else {
		// A narrowing: saved first, then taken out of the signer's ledger.
		err = ls.ledger.CommitEntries(ctx, tenantID, by.String(), nil, entries, "", revoke)
	}
	if err != nil {
		return nil, err
	}
	l, err := ls.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if ls.notify != nil {
		ls.notify(ctx, tenantID, "Authorization letter revoked",
			fmt.Sprintf("%s: %d scope entries naming it no longer authorize scans", l.Title, len(entries)))
	}
	return l, nil
}
