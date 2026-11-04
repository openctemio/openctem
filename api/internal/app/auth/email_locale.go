package auth

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	emaildom "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// localeLookupTimeout bounds the language lookup so a slow database never
// holds up an e-mail.
const localeLookupTimeout = 2 * time.Second

// EmailLocaleResolver picks the language an e-mail is written in. Both methods
// always return a supported locale ("en" or "vi"): a failed lookup is "en",
// never an error, so e-mail is never blocked on it.
type EmailLocaleResolver interface {
	// LocaleForEmail resolves for a recipient known by address: the
	// recipient's own language, else the organization default of tenantID
	// (when not empty), else "en".
	LocaleForEmail(ctx context.Context, recipientEmail, tenantID string) string
	// LocaleForUser is the same for a recipient known by user id.
	LocaleForUser(ctx context.Context, userID, tenantID string) string
}

type localeUserReader interface {
	GetByID(ctx context.Context, id shared.ID) (*user.User, error)
	GetByEmail(ctx context.Context, email string) (*user.User, error)
}

type localeTenantReader interface {
	GetByID(ctx context.Context, id shared.ID) (*tenant.Tenant, error)
}

// RepoEmailLocaleResolver resolves from the user and tenant repositories.
//
// Tenant safety: the organization default is read only for the tenant id the
// e-mail is already being sent for. The address is looked up only among
// accounts (an account is global, one address is one account); it is never
// used to search organizations.
type RepoEmailLocaleResolver struct {
	users   localeUserReader
	tenants localeTenantReader
	log     *logger.Logger
}

// NewRepoEmailLocaleResolver builds the resolver. Either repository may be nil.
func NewRepoEmailLocaleResolver(users localeUserReader, tenants localeTenantReader, log *logger.Logger) *RepoEmailLocaleResolver {
	return &RepoEmailLocaleResolver{users: users, tenants: tenants, log: log}
}

// LocaleForEmail implements EmailLocaleResolver.
func (r *RepoEmailLocaleResolver) LocaleForEmail(ctx context.Context, recipientEmail, tenantID string) string {
	ctx, cancel := context.WithTimeout(ctx, localeLookupTimeout)
	defer cancel()
	if r.users != nil && recipientEmail != "" {
		u, err := r.users.GetByEmail(ctx, recipientEmail)
		if loc := userLanguage(u, err); loc != "" {
			return loc
		}
	}
	return r.orgLocale(ctx, tenantID)
}

// LocaleForUser implements EmailLocaleResolver.
func (r *RepoEmailLocaleResolver) LocaleForUser(ctx context.Context, userID, tenantID string) string {
	ctx, cancel := context.WithTimeout(ctx, localeLookupTimeout)
	defer cancel()
	if r.users != nil && userID != "" {
		if id, err := shared.IDFromString(userID); err == nil {
			u, err := r.users.GetByID(ctx, id)
			if loc := userLanguage(u, err); loc != "" {
				return loc
			}
		}
	}
	return r.orgLocale(ctx, tenantID)
}

// userLanguage is the account's own language, or "" when there is no
// account, the lookup failed, or the user never chose one.
func userLanguage(u *user.User, err error) string {
	if err != nil || u == nil {
		return ""
	}
	return supportedLanguage(u.Preferences().Language)
}

func (r *RepoEmailLocaleResolver) orgLocale(ctx context.Context, tenantID string) string {
	if r.tenants != nil && tenantID != "" {
		if id, err := shared.IDFromString(tenantID); err == nil {
			if t, err := r.tenants.GetByID(ctx, id); err == nil && t != nil {
				if loc := supportedLanguage(t.TypedSettings().General.Language); loc != "" {
					return loc
				}
			}
		}
	}
	return emaildom.DefaultLocale
}

// supportedLanguage is "" for an unset or unsupported language, so that the
// next level of the precedence (organization, then default) applies.
func supportedLanguage(lang string) string {
	if l, ok := emaildom.ParseLocale(lang); ok {
		return l
	}
	return ""
}

// SetLocaleResolver sets how the language of each e-mail is chosen. Without
// one every e-mail is English.
func (s *EmailService) SetLocaleResolver(r EmailLocaleResolver) {
	s.locales = r
}

// localeForEmail never fails: no resolver, or a resolver answer outside the
// catalog, is English.
func (s *EmailService) localeForEmail(ctx context.Context, recipientEmail, tenantID string) string {
	if s.locales == nil {
		return emaildom.DefaultLocale
	}
	return emaildom.NormalizeLocale(s.locales.LocaleForEmail(ctx, recipientEmail, tenantID))
}
