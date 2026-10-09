package scope

// Authorization letters (RFC-065 §13): a client's written permission, such
// as a pentest engagement, uploaded once and named by the scope entries it
// authorizes. An authorization_letter entry authorizes only while its letter
// is valid: from valid_from, before valid_until, and not revoked.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Letter bounds.
const (
	MaxLetterTitle     = 200
	MaxLetterIssuer    = 200
	MaxLetterReference = 200
	// MaxLetterValidity is the longest a letter may authorize.
	MaxLetterValidity = 731 * 24 * time.Hour
)

// LetterContentTypes are the file types a letter may be (the attachment
// storage accepts them too).
var LetterContentTypes = map[string]bool{"application/pdf": true, "image/png": true, "image/jpeg": true}

// Letter errors.
var (
	ErrLetterNotFound = shared.NewDomainError("LETTER_NOT_FOUND", "authorization letter not found", shared.ErrNotFound)
	ErrLetterNotValid = shared.NewDomainError("LETTER_NOT_VALID",
		"the authorization letter is revoked, expired or not yet valid", shared.ErrValidation)
	ErrLetterRequired = shared.NewDomainError("LETTER_REQUIRED",
		"an authorization_letter entry names its letter (letter_id)", shared.ErrValidation)
	ErrLetterRevoked  = shared.NewDomainError("LETTER_REVOKED", "the authorization letter is already revoked", shared.ErrConflict)
	ErrLetterFileType = shared.NewDomainError("LETTER_FILE_TYPE",
		"an authorization letter is a PDF, PNG or JPEG file", shared.ErrValidation)
)

// Letter is one authorization letter of a tenant.
type Letter struct {
	ID           shared.ID
	TenantID     shared.ID
	Title        string
	Issuer       string
	Reference    string
	ValidFrom    time.Time
	ValidUntil   time.Time
	AttachmentID shared.ID
	FileSHA256   string
	UploadedBy   *shared.ID
	CreatedAt    time.Time
	RevokedAt    *time.Time
	RevokedBy    *shared.ID
}

// ValidateLetterDetails checks a new letter's fields.
func ValidateLetterDetails(title, issuer, reference string, validFrom, validUntil, now time.Time) error {
	switch {
	case strings.TrimSpace(title) == "" || len(title) > MaxLetterTitle:
		return fmt.Errorf("%w: title is required (at most %d characters)", shared.ErrValidation, MaxLetterTitle)
	case len(issuer) > MaxLetterIssuer:
		return fmt.Errorf("%w: issuer must be at most %d characters", shared.ErrValidation, MaxLetterIssuer)
	case len(reference) > MaxLetterReference:
		return fmt.Errorf("%w: reference must be at most %d characters", shared.ErrValidation, MaxLetterReference)
	case validUntil.IsZero() || !validUntil.After(now):
		return fmt.Errorf("%w: valid_until must be in the future", shared.ErrValidation)
	case !validUntil.After(validFrom):
		return fmt.Errorf("%w: valid_until must be after valid_from", shared.ErrValidation)
	case validUntil.Sub(validFrom) > MaxLetterValidity:
		return fmt.Errorf("%w: a letter authorizes for at most 2 years", shared.ErrValidation)
	}
	return nil
}

// InEffect reports whether the letter authorizes now.
func (l *Letter) InEffect(now time.Time) bool {
	return l != nil && l.RevokedAt == nil && !now.Before(l.ValidFrom) && now.Before(l.ValidUntil)
}

// LetterRepository persists letters. Every method is tenant-scoped.
type LetterRepository interface {
	Create(ctx context.Context, l *Letter) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Letter, error)
	List(ctx context.Context, tenantID shared.ID) ([]*Letter, error)
	// Revoke sets revoked_at/by when the letter is not revoked yet; it
	// reports ErrLetterRevoked otherwise.
	Revoke(ctx context.Context, tenantID, id, by shared.ID, at time.Time) error
	// EntryIDs lists the scope entries that name the letter.
	EntryIDs(ctx context.Context, tenantID, id shared.ID) ([]shared.ID, error)
}
