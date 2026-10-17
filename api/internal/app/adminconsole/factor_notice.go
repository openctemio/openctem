package adminconsole

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

// Kinds of factor change an administrator is told about by email, so a
// takeover that adds its own key or replaces the recovery codes is noticed.
const (
	FactorKeyAdded                 = "security_key_added"
	FactorRecoveryCodesRegenerated = "recovery_codes_regenerated"
)

// FactorNotice describes one change to an administrator's console factors.
type FactorNotice struct {
	AdminEmail string
	AdminName  string
	Kind       string
	// Detail is the key's name for FactorKeyAdded.
	Detail string
	IP     string
	At     time.Time
}

// FactorChangeNotifier emails the administrator whose factors changed. It is
// called after the change committed; implementations must not block and
// failures are only logged.
type FactorChangeNotifier interface {
	NotifyFactorChange(ctx context.Context, n FactorNotice) error
}

// SetFactorChangeNotifier wires the notifier (email in production).
func (s *Service) SetFactorChangeNotifier(n FactorChangeNotifier) { s.factorNotifier = n }

// SetWebAuthnGrace overrides admin.DefaultWebAuthnGrace for policy switches
// made from now on.
func (s *Service) SetWebAuthnGrace(d time.Duration) { s.grace = d }

func (s *Service) webauthnGrace() time.Duration {
	if s.grace > 0 {
		return s.grace
	}
	return admin.DefaultWebAuthnGrace
}

func (s *Service) notifyFactorChange(ctx context.Context, a *admin.AdminUser, kind, detail string, client ClientInfo) {
	if s.factorNotifier == nil {
		return
	}
	if err := s.factorNotifier.NotifyFactorChange(ctx, FactorNotice{
		AdminEmail: a.Email(), AdminName: a.Name(), Kind: kind, Detail: detail, IP: client.IP, At: s.now(),
	}); err != nil {
		s.log.Warn("email administrator about a console factor change", "kind", kind, "error", err)
	}
}
