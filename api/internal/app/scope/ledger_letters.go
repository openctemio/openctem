package scope

// Letter entries in the job signer's scope ledger (RFC-065 §13, RFC-040
// §11.5): an authorization_letter entry is in effect only while its letter
// is, so the ledger holds it only then, and never past the letter's end:
// the signer stops signing for it when the letter expires even before the
// next ledger sync. A revoked letter takes its entries out
// (LetterService.Revoke).

import (
	"context"
	"time"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// letterBound is e bounded by t's letter: nil when t names a letter that is
// not in effect (or cannot be read: fail closed), e with its expiry no
// later than the letter's end otherwise. e of an entry without a letter is
// returned as is.
func (s *Service) letterBound(ctx context.Context, t *scopedom.Target, e *jobsign.LedgerEntry, now time.Time) *jobsign.LedgerEntry {
	if e == nil || t == nil || t.LetterID() == nil {
		return e
	}
	if s.letters == nil {
		return nil
	}
	l, err := s.letters.GetByID(ctx, t.TenantID(), *t.LetterID())
	if err != nil || l == nil || !l.InEffect(now) {
		return nil
	}
	if e.ExpiresAt != nil && !l.ValidUntil.Before(*e.ExpiresAt) {
		return e
	}
	until := l.ValidUntil.UTC()
	bounded := *e
	bounded.ExpiresAt = &until
	return &bounded
}
