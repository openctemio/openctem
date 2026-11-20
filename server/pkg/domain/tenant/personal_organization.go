package tenant

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The personal organization at sign-up (docs/architecture/user-onboarding.md,
// "Personal organization at sign-up"): when the sign-up policy has the switch
// on, a person who signed up with no other way in gets their own
// organization once their e-mail address is verified.
//
// An account is marked when it is created by self-service sign-up (pending);
// the organization is made at most once per account, at a sign-in, in one
// transaction that also settles the mark. An account created any other way
// (invitation, organization SSO, verified domain, the platform console) is
// never marked, so it never gets one.

// PersonalOrgStatus is the state of an account's mark.
type PersonalOrgStatus string

const (
	// PersonalOrgPending: the account may still get its organization.
	PersonalOrgPending PersonalOrgStatus = "pending"
	// PersonalOrgCreated: the organization was made (it may have been
	// deleted since; it is never made again).
	PersonalOrgCreated PersonalOrgStatus = "created"
	// PersonalOrgSkipped: the account joined or created an organization
	// another way first.
	PersonalOrgSkipped PersonalOrgStatus = "skipped"
)

// PersonalOrgMarkLifetime is how long a pending mark is honored, counted
// from the sign-up. A person who never signed in again for this long (or who
// joined an organization and was removed from it months later) keeps the
// normal "create your organization" step instead of getting one by surprise.
const PersonalOrgMarkLifetime = 30 * 24 * time.Hour

// PersonalOrgRates bounds how many personal organizations are made per
// network prefix and per e-mail domain in a rolling hour. Zero means no
// bound. The domain bound never applies to a consumer mailbox provider
// (gmail.com, outlook.com): one such domain holds a large share of all
// sign-ups, so a shared bound would be spent by normal volume or by one
// person with many accounts. The prefix bound still covers those. Above a bound nothing is made and the account stays pending.
type PersonalOrgRates struct {
	PerPrefix int
	PerDomain int
	Window    time.Duration
}

// PersonalOrgCreation is one personal organization to make.
type PersonalOrgCreation struct {
	UserID     shared.ID
	Email      string
	Tenant     *Tenant
	Membership *Membership
	// EmailDomain and IPPrefix are the reduced forms kept for the rate
	// bounds (signupevent.EmailDomain, signupevent.IPPrefix); IPPrefix may be
	// empty when the address is unknown.
	EmailDomain string
	IPPrefix    string
	Rates       PersonalOrgRates
	At          time.Time
}

var (
	// ErrPersonalOrgNotPending: the account is not marked, or its mark is
	// settled (made already, or skipped). Nothing was written.
	ErrPersonalOrgNotPending = errors.New("personal organization: not pending")
	// ErrPersonalOrgHasMembership: the account belongs to an organization;
	// the mark is settled as skipped.
	ErrPersonalOrgHasMembership = errors.New("personal organization: the account already has an organization")
	// ErrPersonalOrgInvited: an invitation (or an ownership invitation)
	// waits for the account; nothing is made and the mark stays pending.
	ErrPersonalOrgInvited = errors.New("personal organization: an invitation waits")
	// ErrPersonalOrgDomainClaimed: an organization verified the address's
	// domain (rechecked inside the transaction); the person joins that
	// organization instead. The mark stays pending.
	ErrPersonalOrgDomainClaimed = errors.New("personal organization: the e-mail domain is claimed")
	// ErrPersonalOrgRateLimited: a rate bound is reached; the mark stays
	// pending.
	ErrPersonalOrgRateLimited = errors.New("personal organization: rate bound reached")
	// ErrPersonalOrgSlugTaken: the generated address is taken; the caller
	// tries another.
	ErrPersonalOrgSlugTaken = errors.New("personal organization: address taken")
)

// PersonalOrgRepository stores the marks and makes the organization.
type PersonalOrgRepository interface {
	// ReservePersonalOrganization marks a new account (pending). A second
	// call keeps the first mark.
	ReservePersonalOrganization(ctx context.Context, userID shared.ID, at time.Time) error
	// PersonalOrganizationPending reports, at time at, whether the account is marked and
	// not settled and was reserved less than PersonalOrgMarkLifetime before at.
	PersonalOrganizationPending(ctx context.Context, userID shared.ID, at time.Time) (bool, error)
	// CreatePersonalOrganization makes the organization and its owner, and
	// settles the mark, in one transaction that holds the mark's row lock:
	// two sign-ins at once make one organization. It re-checks membership
	// invitations, claimed domains and the mark's age inside the transaction.
	CreatePersonalOrganization(ctx context.Context, c PersonalOrgCreation) error
}

// maxOrgNameRunes keeps the generated name inside the organization name
// limit with room for the wording around it.
const maxOrgNameRunes = 60

// PersonalOrgName is the organization's name from the person's display name
// (the e-mail's local part when they have none), in their language: English
// unless they chose Vietnamese. It can be renamed later.
func PersonalOrgName(displayName, email, language string) string {
	name := strings.Join(strings.FieldsFunc(displayName, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
	if name == "" {
		name, _, _ = strings.Cut(email, "@")
	}
	if utf8.RuneCountInString(name) > maxOrgNameRunes {
		name = strings.TrimSpace(string([]rune(name)[:maxOrgNameRunes]))
	}
	if name == "" {
		name = "My"
		if language == "vi" {
			return "Tổ chức của tôi"
		}
		return "My organization"
	}
	if language == "vi" {
		return "Tổ chức của " + name
	}
	return name + "'s organization"
}

// slugSuffixAlphabet has no look-alike characters.
const slugSuffixAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// PersonalOrgSlug is the organization's address: the name's ASCII letters
// and digits (at most 30) and a random suffix, so it says nothing about
// other organizations and is hard to guess. The base falls back to "org".
func PersonalOrgSlug(displayName, email string) (string, error) {
	base := GenerateSlug(asciiFold(displayName))
	if base == "" {
		local, _, _ := strings.Cut(email, "@")
		base = GenerateSlug(asciiFold(local))
	}
	if len(base) > 30 {
		base = strings.Trim(base[:30], "-")
	}
	if base == "" {
		base = "org"
	}
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	suffix := make([]byte, len(buf))
	for i, b := range buf {
		suffix[i] = slugSuffixAlphabet[int(b)%len(slugSuffixAlphabet)]
	}
	return base + "-" + string(suffix), nil
}

// asciiFold drops diacritics from the Latin letters people commonly use
// (Vietnamese included) and keeps the rest as is; GenerateSlug drops what
// is still not a-z or 0-9.
func asciiFold(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if f, ok := foldRunes[r]; ok {
			b.WriteRune(f)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

var foldRunes = func() map[rune]rune {
	m := map[rune]rune{'đ': 'd'}
	groups := map[rune]string{
		'a': "àáạảãâầấậẩẫăằắặẳẵäå",
		'e': "èéẹẻẽêềếệểễë",
		'i': "ìíịỉĩïî",
		'o': "òóọỏõôồốộổỗơờớợởỡöø",
		'u': "ùúụủũưừứựửữüû",
		'y': "ỳýỵỷỹÿ",
		'c': "ç",
		'n': "ñ",
	}
	for base, rs := range groups {
		for _, r := range rs {
			m[r] = base
		}
	}
	return m
}()
