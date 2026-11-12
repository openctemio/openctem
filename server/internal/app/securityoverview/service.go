// Package securityoverview computes the organization's security overview: a
// short list of posture checks (sign-in, people, credentials, scanning,
// organization) with a status each and one score. The server returns ids,
// statuses, counts and links only; the web console renders the wording from
// its dictionaries, so every language gets the same overview.
// See docs/architecture/security-overview.md.
package securityoverview

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Status of one check.
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusRisk Status = "risk"
	// StatusInfo is an optional hardening that is not scored.
	StatusInfo Status = "info"
)

// Check ids. The web console keys its titles and explanations on them.
const (
	CheckMFAAdminsRequired = "sign_in.mfa_admins_required"
	CheckAdminsWithoutMFA  = "sign_in.admins_without_mfa"
	CheckEmailVerification = "sign_in.email_verification"
	CheckIPAllowlist       = "sign_in.ip_allowlist"
	CheckDormantMembers    = "people.dormant_members"
	CheckJoinRequests      = "people.join_requests"
	CheckAPIKeysExpiring   = "credentials.api_keys_expiring"
	CheckAPIKeysUnused     = "credentials.api_keys_unused"
	CheckSCIMTokensUnused  = "credentials.scim_tokens_unused"
	CheckSensorOptIns      = "scanning.sensor_opt_ins"
	CheckPrivateTargetRule = "scanning.private_target_policy"
	CheckVerifiedDomain    = "organization.verified_domain"
	CheckSupportAccess     = "organization.support_access"
)

// Score weights and the time windows of the count queries.
const (
	scoreWeightRisk = 3
	scoreWeightWarn = 1

	// APIKeyExpiryWindow is how soon a key must expire to be listed.
	APIKeyExpiryWindow = 14 * 24 * time.Hour
	// UnusedAfter is how long a key, token or member may sit unused.
	UnusedAfter = 90 * 24 * time.Hour
	// NeverUsedGrace is how long a new key, token or member may stay unused
	// before "never used" counts.
	NeverUsedGrace = 30 * 24 * time.Hour
)

// Groups, in display order.
const (
	GroupSignIn       = "sign_in"
	GroupPeople       = "people"
	GroupCredentials  = "credentials"
	GroupScanning     = "scanning"
	GroupOrganization = "organization"
)

// Check is one line of the overview. Count is set when the check counts
// something (members, keys, tokens, grants).
type Check struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Status Status `json:"status"`
	Count  *int   `json:"count,omitempty"`
	Link   string `json:"link"`
}

// Counts is what the tenant-scoped count queries return. The time windows are
// the constants above, evaluated against the time passed to Counts.
type Counts struct {
	// AdminsWithoutMFA: active owners and administrators with a local account
	// and no second factor (accounts that sign in through an identity provider
	// are covered by it).
	AdminsWithoutMFA int
	// DormantMembers: active people who have not signed in for UnusedAfter,
	// or never signed in and joined more than NeverUsedGrace ago.
	DormantMembers      int
	PendingJoinRequests int
	APIKeysExpiring     int
	APIKeysUnused       int
	SCIMTokensActive    int
	SCIMTokensUnused    int
	VerifiedDomains     int
	ActiveSupportGrants int
}

// Counter counts the tenant's rows. Every query carries the tenant.
type Counter interface {
	Counts(ctx context.Context, tenantID shared.ID, now time.Time) (Counts, error)
}

// TenantReader loads the organization (its security settings).
type TenantReader interface {
	GetTenant(ctx context.Context, tenantID string) (*tenant.Tenant, error)
}

// Overview is the response.
type Overview struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Score       int          `json:"score"`
	Counts      StatusCounts `json:"counts"`
	Checks      []Check      `json:"checks"`
}

// StatusCounts is how many checks have each status.
type StatusCounts struct {
	Risk int `json:"risk"`
	Warn int `json:"warn"`
	Pass int `json:"pass"`
	Info int `json:"info"`
}

// Service computes the overview.
type Service struct {
	tenants TenantReader
	counter Counter
	now     func() time.Time
}

// NewService returns the service. A nil dependency omits the checks that
// need it instead of failing the overview.
func NewService(tenants TenantReader, counter Counter) *Service {
	return &Service{tenants: tenants, counter: counter, now: time.Now}
}

// Get computes the overview of one organization.
func (s *Service) Get(ctx context.Context, tenantID shared.ID) (*Overview, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant required", shared.ErrValidation)
	}
	now := s.now().UTC()
	var sec *tenant.SecuritySettings
	if s.tenants != nil {
		t, err := s.tenants.GetTenant(ctx, tenantID.String())
		if err != nil {
			return nil, fmt.Errorf("load organization: %w", err)
		}
		v := t.TypedSettings().Security
		sec = &v
	}
	var counts *Counts
	if s.counter != nil {
		c, err := s.counter.Counts(ctx, tenantID, now)
		if err != nil {
			return nil, fmt.Errorf("count: %w", err)
		}
		counts = &c
	}
	return Evaluate(sec, counts, now), nil
}

func intp(n int) *int { return &n }

func countStatus(n int, whenPositive Status) Status {
	if n > 0 {
		return whenPositive
	}
	return StatusPass
}

// Evaluate builds the overview from settings and counts; either may be nil
// (its checks are omitted).
func Evaluate(sec *tenant.SecuritySettings, c *Counts, now time.Time) *Overview {
	var checks []Check
	add := func(id, group string, st Status, count *int, link string) {
		checks = append(checks, Check{ID: id, Group: group, Status: st, Count: count, Link: link})
	}
	// Each link opens the page at the setting (the web settings anchors).
	const (
		linkTwoFactor     = "/settings/authentication#two-factor"
		linkEmailVerify   = "/settings/authentication#email-verification"
		linkIPAllowlist   = "/settings/authentication#ip-allowlist"
		linkSensorOptIns  = "/settings/scanning/sensor-safety#opt-ins"
		linkPrivateTarget = "/settings/scanning/sensor-safety#private-targets"
		linkMembers       = "/settings/members"
		linkKeys          = "/settings/api-keys"
	)

	if sec != nil {
		st := StatusRisk
		if sec.MFARequired || sec.MFARequiredForAdmins {
			st = StatusPass
		}
		add(CheckMFAAdminsRequired, GroupSignIn, st, nil, linkTwoFactor)
	}
	if c != nil {
		add(CheckAdminsWithoutMFA, GroupSignIn, countStatus(c.AdminsWithoutMFA, StatusRisk), intp(c.AdminsWithoutMFA), linkMembers)
	}
	if sec != nil {
		st := StatusPass
		if sec.EmailVerificationMode == tenant.EmailVerificationNever {
			st = StatusWarn
		}
		add(CheckEmailVerification, GroupSignIn, st, nil, linkEmailVerify)
		st = StatusInfo
		if len(sec.IPWhitelist) > 0 {
			st = StatusPass
		}
		add(CheckIPAllowlist, GroupSignIn, st, nil, linkIPAllowlist)
	}
	if c != nil {
		add(CheckDormantMembers, GroupPeople, countStatus(c.DormantMembers, StatusWarn), intp(c.DormantMembers), linkMembers)
		add(CheckJoinRequests, GroupPeople, countStatus(c.PendingJoinRequests, StatusWarn), intp(c.PendingJoinRequests), linkMembers)
		add(CheckAPIKeysExpiring, GroupCredentials, countStatus(c.APIKeysExpiring, StatusWarn), intp(c.APIKeysExpiring), linkKeys)
		add(CheckAPIKeysUnused, GroupCredentials, countStatus(c.APIKeysUnused, StatusWarn), intp(c.APIKeysUnused), linkKeys)
		st := countStatus(c.SCIMTokensUnused, StatusWarn)
		if c.SCIMTokensActive == 0 {
			st = StatusInfo
		}
		add(CheckSCIMTokensUnused, GroupCredentials, st, intp(c.SCIMTokensUnused), "/settings/scim")
	}
	if sec != nil {
		st := StatusPass
		if sec.AllowSensorInteractsh || sec.AllowSensorCustomTemplates {
			st = StatusWarn
		}
		add(CheckSensorOptIns, GroupScanning, st, nil, linkSensorOptIns)
		st = StatusPass
		if !sec.RequireSensorLocalPolicyForPrivateTargets {
			st = StatusInfo
		}
		add(CheckPrivateTargetRule, GroupScanning, st, nil, linkPrivateTarget)
	}
	if c != nil {
		st := StatusInfo
		if c.VerifiedDomains > 0 {
			st = StatusPass
		}
		add(CheckVerifiedDomain, GroupOrganization, st, intp(c.VerifiedDomains), "/settings/domains")
		add(CheckSupportAccess, GroupOrganization, countStatus(c.ActiveSupportGrants, StatusWarn), intp(c.ActiveSupportGrants), "/settings/support-access")
	}

	o := &Overview{GeneratedAt: now, Checks: checks}
	if o.Checks == nil {
		o.Checks = []Check{}
	}
	var penalty, maxPenalty int
	for _, ch := range checks {
		switch ch.Status {
		case StatusRisk:
			o.Counts.Risk++
			penalty += scoreWeightRisk
			maxPenalty += scoreWeightRisk
		case StatusWarn:
			o.Counts.Warn++
			penalty += scoreWeightWarn
			maxPenalty += scoreWeightWarn
		case StatusPass:
			o.Counts.Pass++
			// A passed check could have been a risk or a warning: it weighs
			// what it guards against.
			maxPenalty += passWeight(ch.ID)
		case StatusInfo:
			o.Counts.Info++
		}
	}
	o.Score = score(penalty, maxPenalty)
	return o
}

// score is round(100 * (1 - penalty/maxPenalty)); no scored checks is 100.
func score(penalty, maxPenalty int) int {
	if maxPenalty <= 0 {
		return 100
	}
	return int(math.Round(100 * (1 - float64(penalty)/float64(maxPenalty))))
}

// passWeight is the weight a passed check would have carried had it failed:
// risk checks weigh 3, warning checks 1.
func passWeight(id string) int {
	switch id {
	case CheckMFAAdminsRequired, CheckAdminsWithoutMFA:
		return scoreWeightRisk
	}
	return scoreWeightWarn
}
