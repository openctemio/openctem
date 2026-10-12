// Package accessrequest runs the request-access queue: people who cannot sign
// up (sign-up policy admin_only, request access on) ask for an organization;
// a platform administrator approves (the organization is created with the
// requester as owner) or rejects (docs/architecture/user-onboarding.md,
// "Request access").
//
// The public side never tells the caller what happened to the request: an
// accepted, rate-limited, disposable-address or duplicate submission all get
// the same answer.
package accessrequest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/crypto"
	ardom "github.com/openctemio/openctem/api/pkg/domain/accessrequest"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/emaildomain"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Errors the handlers map.
var (
	// ErrClosed: the sign-up policy does not take requests (self_service, or
	// request access off).
	ErrClosed = fmt.Errorf("%w: access requests are not accepted", shared.ErrForbidden)
	// ErrCaptcha: the CAPTCHA was missing or failed.
	ErrCaptcha = fmt.Errorf("%w: the CAPTCHA check failed", shared.ErrValidation)
)

// Captcha verifies a CAPTCHA token (Cloudflare Turnstile in production).
type Captcha interface {
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

// Mailer sends the requester's emails. Implementations send asynchronously.
type Mailer interface {
	Configured() bool
	SendConfirmation(ctx context.Context, to, company, confirmURL string) error
	SendDecision(ctx context.Context, to string, approved bool) error
}

// OrgCreator creates the organization on approval (tenant.OrganizationCreator).
type OrgCreator interface {
	Create(ctx context.Context, in tenantapp.CreateOrganizationInput, actx auditapp.AuditContext) (*tenantapp.CreatedOrganization, error)
}

// Service runs the queue.
type Service struct {
	repo    ardom.Repository
	policy  signupdom.PolicySource
	orgs    OrgCreator
	mailer  Mailer
	captcha Captcha
	baseURL string
	log     *logger.Logger
	now     func() time.Time
}

// NewService creates the service. mailer and captcha may be nil (no email:
// requests skip confirmation; no CAPTCHA configured).
func NewService(repo ardom.Repository, policy signupdom.PolicySource, orgs OrgCreator, mailer Mailer, captcha Captcha, baseURL string, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, policy: policy, orgs: orgs, mailer: mailer, captcha: captcha,
		baseURL: strings.TrimSuffix(baseURL, "/"), log: log.With("service", "access_request"), now: time.Now}
}

// Open reports whether requests are accepted now.
func (s *Service) Open(ctx context.Context) bool {
	p := s.policy.Current(ctx)
	return p.RequestAccess && !p.AllowsSelfService()
}

// SubmitInput is a public submission.
type SubmitInput struct {
	Company      string
	Email        string
	Note         string
	CaptchaToken string
	IP           string
}

func ipHash(ip string) string {
	if ip == "" {
		return ""
	}
	return crypto.HashToken("access-request-ip:" + ip)
}

// Submit records a request. It returns ErrClosed, ErrCaptcha or ErrInvalid
// for a refusal the caller may know about; every other outcome (stored,
// over a rate limit, disposable address) returns nil, so the answer does not
// reveal anything.
func (s *Service) Submit(ctx context.Context, in SubmitInput) error {
	if !s.Open(ctx) {
		return ErrClosed
	}
	company := strings.TrimSpace(in.Company)
	email := strings.ToLower(strings.TrimSpace(in.Email))
	note := strings.TrimSpace(in.Note)
	domain := ardom.EmailDomain(email)
	if company == "" || len([]rune(company)) > ardom.MaxCompanyLen || len([]rune(note)) > ardom.MaxNoteLen ||
		domain == "" || len(email) > 254 || strings.Count(email, "@") != 1 || strings.ContainsAny(email, " \t\r\n<>") {
		return ardom.ErrInvalid
	}
	if s.captcha != nil {
		ok, err := s.captcha.Verify(ctx, in.CaptchaToken, in.IP)
		if err != nil || !ok {
			return ErrCaptcha
		}
	}

	now := s.now().UTC()
	hash := ipHash(in.IP)
	if emaildomain.IsDisposable(domain) {
		s.log.Info("access request dropped: disposable address")
		return nil
	}
	if hash != "" {
		if n, err := s.repo.CountByIPSince(ctx, hash, now.Add(-time.Hour)); err != nil || n >= ardom.MaxPerIPPerHour {
			s.log.Info("access request dropped: per-address limit", "error", err)
			return nil
		}
	}
	if n, err := s.repo.CountByDomainSince(ctx, domain, now.Add(-24*time.Hour)); err != nil || n >= ardom.MaxPerDomainPerDay {
		s.log.Info("access request dropped: per-domain limit", "error", err)
		return nil
	}

	req := &ardom.Request{
		ID: shared.NewID(), Company: company, Email: email, Domain: domain, Note: note,
		Status: ardom.StatusPending, IPHash: hash, CreatedAt: now,
	}
	var token string
	confirm := s.mailer != nil && s.mailer.Configured()
	if confirm {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate token: %w", err)
		}
		token = base64.RawURLEncoding.EncodeToString(b)
		req.Status = ardom.StatusUnconfirmed
		req.ConfirmHash = crypto.HashToken(token)
	}
	if err := s.repo.Create(ctx, req); err != nil {
		return err
	}
	if confirm {
		// The token rides in the URL fragment: it never reaches a server log.
		link := s.baseURL + "/request-access/confirm#token=" + token
		if err := s.mailer.SendConfirmation(ctx, email, company, link); err != nil {
			s.log.Warn("access request confirmation email failed", "error", logger.SanitizeError(err))
		}
	}
	s.log.Info("access request received", "id", req.ID.String(), "confirm", confirm)
	return nil
}

// Confirm marks a request confirmed by its emailed token.
func (s *Service) Confirm(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 200 {
		return ardom.ErrInvalidToken
	}
	req, err := s.repo.GetByConfirmHash(ctx, crypto.HashToken(token))
	if err != nil {
		return ardom.ErrInvalidToken
	}
	now := s.now().UTC()
	if req.Status != ardom.StatusUnconfirmed || now.Sub(req.CreatedAt) > ardom.UnconfirmedTTL {
		return ardom.ErrInvalidToken
	}
	req.Status = ardom.StatusPending
	req.ConfirmHash = ""
	req.ConfirmedAt = &now
	if err := s.repo.Update(ctx, req, ardom.StatusUnconfirmed); err != nil {
		return ardom.ErrInvalidToken
	}
	return nil
}

// List returns requests for the console.
func (s *Service) List(ctx context.Context, f ardom.Filter) ([]*ardom.Request, int, error) {
	return s.repo.List(ctx, f)
}

// ApproveInput names the organization created for a request.
type ApproveInput struct {
	Name string
	Slug string
}

// Approve creates the organization with the requester as its owner (one-time
// set-password link for a new account) and closes the request. Only a
// pending (confirmed) request can be approved.
func (s *Service) Approve(ctx context.Context, actor *admin.AdminUser, id shared.ID, in ApproveInput, actx auditapp.AuditContext) (*ardom.Request, *tenantapp.CreatedOrganization, error) {
	req, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if req.Status != ardom.StatusPending {
		return nil, nil, ardom.ErrNotDecidable
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = req.Company
	}
	// Claim the request first, so two administrators approving at once
	// cannot create two organizations; put it back if creation fails.
	now := s.now().UTC()
	by := actor.ID()
	req.Status, req.DecidedAt, req.DecidedBy = ardom.StatusApproved, &now, &by
	if err := s.repo.Update(ctx, req, ardom.StatusPending); err != nil {
		return nil, nil, err
	}
	created, err := s.orgs.Create(ctx, tenantapp.CreateOrganizationInput{
		Name: name, Slug: strings.ToLower(strings.TrimSpace(in.Slug)), OwnerEmail: req.Email,
		Description: "Created from an access request",
	}, actx)
	if err != nil {
		req.Status, req.DecidedAt, req.DecidedBy = ardom.StatusPending, nil, nil
		if rerr := s.repo.Update(ctx, req, ardom.StatusApproved); rerr != nil {
			s.log.Error("return access request to pending after a failed approval", "id", req.ID.String(), "error", rerr)
		}
		return nil, nil, err
	}
	tid := created.Tenant.ID()
	req.TenantID = &tid
	if err := s.repo.Update(ctx, req, ardom.StatusApproved); err != nil {
		s.log.Error("record the organization of an approved access request", "id", req.ID.String(), "error", err)
	}
	return req, created, nil
}

// Reject closes a pending or unconfirmed request; the requester gets a
// neutral email.
func (s *Service) Reject(ctx context.Context, actor *admin.AdminUser, id shared.ID) (*ardom.Request, error) {
	req, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if req.Status != ardom.StatusPending && req.Status != ardom.StatusUnconfirmed {
		return nil, ardom.ErrNotDecidable
	}
	wasConfirmed := req.Status == ardom.StatusPending
	now := s.now().UTC()
	by := actor.ID()
	from := req.Status
	req.Status, req.DecidedAt, req.DecidedBy, req.ConfirmHash = ardom.StatusRejected, &now, &by, ""
	if err := s.repo.Update(ctx, req, from); err != nil {
		return nil, err
	}
	// Only someone who proved the address hears back.
	if wasConfirmed && s.mailer != nil && s.mailer.Configured() {
		if err := s.mailer.SendDecision(ctx, req.Email, false); err != nil {
			s.log.Warn("access request decision email failed", "error", logger.SanitizeError(err))
		}
	}
	return req, nil
}

// Purge applies the retention: unconfirmed after 24 h, decided after 90 days.
func (s *Service) Purge(ctx context.Context) (int64, error) {
	now := s.now().UTC()
	return s.repo.Purge(ctx, now.Add(-ardom.UnconfirmedTTL), now.Add(-ardom.DecidedRetention))
}
