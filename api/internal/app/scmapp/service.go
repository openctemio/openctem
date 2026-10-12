// Package scmapp binds code-host app installations to organizations and
// handles the code host's installation webhooks
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, section 3.3).
//
// Binding needs two proofs from the person completing the install: a state
// the console signed for them and their organization (so a setup redirect
// cannot be replayed into another organization), and their own GitHub
// authorization showing they can access the installation (so a guessed
// installation id cannot be claimed). One installation belongs to at most one
// organization.
package scmapp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/scm/githubapp"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// StateTTL bounds how long an install link stays usable.
const StateTTL = 15 * time.Minute

// GitHubApp is the part of the GitHub App client the service uses.
type GitHubApp interface {
	Slug() string
	InstallURL(state string) string
	GetInstallation(ctx context.Context, id int64) (*githubapp.Installation, error)
	UserCanAccessInstallation(ctx context.Context, code string, installationID int64) (bool, error)
	VerifySignature(body []byte, header string) bool
	ForgetInstallation(id int64)
}

// Auditor writes audit records.
type Auditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Actor is who acts.
type Actor struct {
	UserID    string
	Email     string
	IP        string
	UserAgent string
}

// Service manages installations.
type Service struct {
	repo     scmapp.Repository
	github   GitHubApp // nil when the deployment has no GitHub App
	stateKey []byte
	audit    Auditor
	log      *logger.Logger
	now      func() time.Time
}

// NewService creates the service. stateSecret signs install states (a
// deployment secret; a domain-separated key is derived from it).
func NewService(repo scmapp.Repository, github GitHubApp, stateSecret string, audit Auditor, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	k := sha256.Sum256([]byte("openctem-scm-app-install-state\x00" + stateSecret))
	return &Service{repo: repo, github: github, stateKey: k[:], audit: audit, log: log.With("service", "scmapp"), now: time.Now}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// GitHubConfigured reports whether the deployment has a GitHub App.
func (s *Service) GitHubConfigured() bool { return s.github != nil }

// GitHubSlug is the app's name on GitHub ("" when not configured).
func (s *Service) GitHubSlug() string {
	if s.github == nil {
		return ""
	}
	return s.github.Slug()
}

type installState struct {
	TenantID string `json:"t"`
	UserID   string `json:"u"`
	Expires  int64  `json:"e"`
	Nonce    string `json:"n"`
}

func (s *Service) sign(payload string) string {
	m := hmac.New(sha256.New, s.stateKey)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

// GitHubInstallURL returns the link that installs the app for the tenant;
// the state it carries is bound to the person and expires in StateTTL.
func (s *Service) GitHubInstallURL(tenantID shared.ID, userID string) (string, error) {
	if s.github == nil {
		return "", githubapp.ErrNotConfigured
	}
	if userID == "" {
		return "", scmapp.ErrNotAuthorized
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	b, _ := json.Marshal(installState{TenantID: tenantID.String(), UserID: userID,
		Expires: s.now().Add(StateTTL).Unix(), Nonce: hex.EncodeToString(nonce)})
	payload := base64.RawURLEncoding.EncodeToString(b)
	return s.github.InstallURL(payload + "." + s.sign(payload)), nil
}

func (s *Service) checkState(state string, tenantID shared.ID, userID string) bool {
	payload, sig, ok := strings.Cut(state, ".")
	if !ok || len(state) > 1024 || !hmac.Equal([]byte(sig), []byte(s.sign(payload))) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	var st installState
	if json.Unmarshal(raw, &st) != nil {
		return false
	}
	return st.TenantID == tenantID.String() && st.UserID == userID && s.now().Unix() <= st.Expires
}

// CompleteGitHubInput is the setup redirect's query, posted by the console.
type CompleteGitHubInput struct {
	InstallationID int64
	Code           string
	State          string
}

// CompleteGitHubInstall binds an installation to the tenant after checking
// the state and the person's own access to it on GitHub (audited).
func (s *Service) CompleteGitHubInstall(ctx context.Context, tenantID shared.ID, in CompleteGitHubInput, a Actor) (*scmapp.Installation, error) {
	if s.github == nil {
		return nil, githubapp.ErrNotConfigured
	}
	if in.InstallationID <= 0 || !s.checkState(in.State, tenantID, a.UserID) {
		return nil, scmapp.ErrNotAuthorized
	}
	ok, err := s.github.UserCanAccessInstallation(ctx, in.Code, in.InstallationID)
	if err != nil {
		s.log.Warn("github app install not verified", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return nil, scmapp.ErrNotAuthorized
	}
	if !ok {
		return nil, scmapp.ErrNotAuthorized
	}
	gh, err := s.github.GetInstallation(ctx, in.InstallationID)
	if err != nil {
		return nil, fmt.Errorf("read installation: %w", err)
	}
	var createdBy *shared.ID
	if id, err := shared.IDFromString(a.UserID); err == nil {
		createdBy = &id
	}
	inst := &scmapp.Installation{ID: shared.NewID(), TenantID: tenantID, Provider: scmapp.ProviderGitHub,
		InstallationID: gh.ID, AccountLogin: truncate(gh.Account.Login, 255), AccountID: gh.Account.ID,
		AccountType: truncate(gh.Account.Type, 20), RepositorySelection: truncate(gh.RepositorySelection, 20), CreatedBy: createdBy}
	if err := s.repo.Create(ctx, inst); err != nil {
		if errors.Is(err, scmapp.ErrBoundElsewhere) {
			s.log.Warn("github app installation bound elsewhere", "tenant_id", tenantID.String(), "installation_id", in.InstallationID)
		}
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionSCMAppInstalled, auditdom.ResourceTypeSCMApp, inst.ID.String()).
		WithResourceName(inst.AccountLogin).
		WithMessage(fmt.Sprintf("GitHub App installation on %s bound for CI checks and pull request comments", inst.AccountLogin)).
		WithMetadata("installation_id", inst.InstallationID).
		WithMetadata("repository_selection", inst.RepositorySelection))
	return inst, nil
}

// List returns the tenant's installations.
func (s *Service) List(ctx context.Context, tenantID shared.ID) ([]scmapp.Installation, error) {
	return s.repo.List(ctx, tenantID)
}

// Remove unbinds an installation from the tenant (audited). The app stays
// installed on GitHub until someone removes it there.
func (s *Service) Remove(ctx context.Context, tenantID, id shared.ID, a Actor) error {
	inst, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	if s.github != nil {
		s.github.ForgetInstallation(inst.InstallationID)
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionSCMAppRemoved, auditdom.ResourceTypeSCMApp, id.String()).
		WithResourceName(inst.AccountLogin).
		WithMessage(fmt.Sprintf("GitHub App installation on %s unbound", inst.AccountLogin)).
		WithMetadata("installation_id", inst.InstallationID))
	return nil
}

// ErrBadSignature: a webhook whose signature does not verify.
var ErrBadSignature = errors.New("webhook signature does not verify")

// MaxWebhookBody bounds a webhook delivery.
const MaxWebhookBody = 1 << 20

// HandleGitHubWebhook applies an installation event GitHub sent. The
// signature is checked before the body is parsed; events about other things
// are ignored. Status changes are audited on the bound tenant.
func (s *Service) HandleGitHubWebhook(ctx context.Context, event, signature string, body []byte) error {
	if s.github == nil {
		return githubapp.ErrNotConfigured
	}
	if !s.github.VerifySignature(body, signature) {
		return ErrBadSignature
	}
	if event != "installation" {
		return nil
	}
	var p struct {
		Action       string `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	if err := json.Unmarshal(body, &p); err != nil || p.Installation.ID <= 0 {
		return nil //nolint:nilerr // a verified but unusable delivery is acknowledged and ignored
	}
	status := ""
	switch p.Action {
	case "deleted":
		status = scmapp.StatusDeleted
	case "suspend":
		status = scmapp.StatusSuspended
	case "unsuspend":
		status = scmapp.StatusActive
	default:
		return nil
	}
	inst, err := s.repo.GetByInstallationID(ctx, scmapp.ProviderGitHub, p.Installation.ID)
	if errors.Is(err, scmapp.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	n, err := s.repo.SetStatusByInstallationID(ctx, scmapp.ProviderGitHub, p.Installation.ID, status)
	if err != nil {
		return err
	}
	s.github.ForgetInstallation(p.Installation.ID)
	if n > 0 {
		s.logAudit(ctx, inst.TenantID, Actor{Email: "github"},
			auditapp.NewSuccessEvent(auditdom.ActionSCMAppStatusChanged, auditdom.ResourceTypeSCMApp, inst.ID.String()).
				WithResourceName(inst.AccountLogin).
				WithMessage(fmt.Sprintf("GitHub App installation on %s is now %s", inst.AccountLogin, status)).
				WithMetadata("status", status))
	}
	return nil
}

func (s *Service) logAudit(ctx context.Context, tenantID shared.ID, a Actor, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: a.UserID,
		ActorEmail: a.Email, ActorIP: a.IP, UserAgent: a.UserAgent}, ev); err != nil {
		s.log.Warn("scm app audit record not written", "action", ev.Action.String(), "error", logger.SanitizeError(err))
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
