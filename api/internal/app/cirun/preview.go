package cirun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// Trust preview: an administrator pastes a sample token from a CI job and
// sees what the platform reads from it, whether its signature verifies
// against the issuer's keys and whether the (unsaved) configuration would
// admit it. Nothing is stored or claimed: the token's id is not recorded,
// no run or asset is created, and the token is never logged. The token is
// judged at its own issue time, so a sample that expired since is still
// shown; the result says it expired.

// PreviewInput is a draft configuration and a sample token.
type PreviewInput struct {
	Config  TrustConfigInput
	IDToken string
	Hints   cirun.Hints
}

// PreviewClaims are the normalized claims a preview shows.
type PreviewClaims struct {
	Repository     string `json:"repository"`
	RepositoryID   string `json:"repository_id,omitempty"`
	Owner          string `json:"owner"`
	Ref            string `json:"ref"`
	Branch         string `json:"branch,omitempty"`
	PullRequest    string `json:"pull_request,omitempty"`
	CommitSHA      string `json:"commit_sha,omitempty"`
	CommitVerified bool   `json:"commit_verified"`
	Event          string `json:"event,omitempty"`
	Environment    string `json:"environment,omitempty"`
	RunID          string `json:"run_id,omitempty"`
	RunAttempt     string `json:"run_attempt,omitempty"`
	JobID          string `json:"job_id,omitempty"`
	Organization   string `json:"organization,omitempty"`
	Fork           bool   `json:"fork"`
	PipelineURL    string `json:"pipeline_url,omitempty"`
}

// PreviewRefusal is why the configuration would refuse the token.
type PreviewRefusal struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// PreviewResult is what a preview shows. Claims holds the token's payload as
// sent (signed or not), without personal addresses.
type PreviewResult struct {
	// Verified: the signature, issuer and audience check against the
	// configuration's issuer keys.
	Verified    bool           `json:"verified"`
	VerifyError string         `json:"verify_error,omitempty"`
	Expired     bool           `json:"expired"`
	IssuedAt    *time.Time     `json:"issued_at,omitempty"`
	ExpiresAt   *time.Time     `json:"expires_at,omitempty"`
	Claims      map[string]any `json:"claims"`
	// Normalized and the rest are set only for a verified token.
	Normalized   *PreviewClaims  `json:"normalized,omitempty"`
	Admitted     bool            `json:"admitted"`
	Refusal      *PreviewRefusal `json:"refusal,omitempty"`
	Repository   string          `json:"repository_asset,omitempty"`
	PipelineKey  string          `json:"pipeline_key,omitempty"`
	ReplayKeyJTI bool            `json:"replay_key_from_jti"`
}

// errPreviewToken: the sample is not a readable JWT.
var errPreviewToken = errors.New("the sample is not a JWT")

// personalClaims are never echoed back: a person's address is not needed to
// set up trust.
var personalClaims = map[string]bool{"user_email": true, "email": true}

// PreviewTrust checks a sample token against a draft configuration of the
// tenant. The configuration is validated first (an invalid one is a
// validation error and nothing is fetched), so the keys are only ever read
// from an issuer that a saved configuration could name, through the
// SSRF-guarded client.
func (s *Service) PreviewTrust(ctx context.Context, tenantID shared.ID, in PreviewInput) (*PreviewResult, error) {
	cfg := &cirun.TrustConfig{TenantID: tenantID, Name: in.Config.Name, Provider: cirun.Provider(in.Config.Provider),
		Issuer: in.Config.Issuer, Audience: in.Config.Audience, DefaultBranch: in.Config.DefaultBranch,
		Rules: in.Config.Rules, Enabled: true}
	if strings.TrimSpace(cfg.Name) == "" {
		cfg.Name = "preview"
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	payload, err := unverifiedPayload(in.IDToken)
	if err != nil {
		return nil, errPreviewWrap(err)
	}
	out := &PreviewResult{Claims: payload}
	if s.verifier == nil {
		return nil, errors.New("no token verifier")
	}
	tok, err := s.verifier.VerifyWorkloadToken(ctx, in.IDToken, oidc.WorkloadExpectations{Issuer: cfg.Issuer,
		Audience: cfg.Audience, JTIOptional: cirun.JTIOptional(cfg.Provider), IgnoreTimes: true})
	if err != nil {
		out.VerifyError = previewError(err)
		return out, nil
	}
	out.Verified = true
	iat, exp := tok.IssuedAt.UTC(), tok.ExpiresAt.UTC()
	out.IssuedAt, out.ExpiresAt = &iat, &exp
	out.Expired = s.now().After(tok.ExpiresAt)
	out.ReplayKeyJTI = !strings.HasPrefix(tok.JTI, oidc.TokenHashJTIPrefix)

	c := cirun.ParseClaims(cfg.Provider, tok.Claims)
	c.JTI = tok.JTI
	c.ApplyHints(in.Hints)
	c.Audience = cfg.Audience
	out.Normalized = &PreviewClaims{Repository: c.Repository, RepositoryID: c.RepositoryID, Owner: c.Owner(), Ref: c.Ref,
		Branch: c.Branch, PullRequest: c.PullRequest, CommitSHA: c.SHA, CommitVerified: c.CommitVerified, Event: c.Event,
		Environment: c.Environment, RunID: c.RunID, RunAttempt: c.RunAttempt, JobID: c.JobID, Organization: c.OrgID,
		Fork: c.IsForkEvent(), PipelineURL: cirun.PipelineURL(cfg.Provider, cfg.Issuer, c)}
	if c.Repository != "" {
		out.Repository = asset.NormalizeName(c.CanonicalRepository(), asset.AssetTypeRepository, "")
	}
	key, refusal := previewAdmit(cfg, c)
	if refusal != nil {
		out.Refusal = refusal
		return out, nil
	}
	out.PipelineKey = key.ExternalRepoID + " " + key.WorkflowPath
	out.Admitted = true
	return out, nil
}

// previewAdmit runs the exchange's admission (rules, then the pipeline
// identity) and says why it would refuse.
func previewAdmit(cfg *cirun.TrustConfig, c cirun.Claims) (cirun.PipelineKey, *PreviewRefusal) {
	if r := cfg.Rules.Admit(c); r != nil {
		return cirun.PipelineKey{}, &PreviewRefusal{Code: r.Code, Detail: r.Detail}
	}
	key, r := cirun.PipelineKeyFromClaims(cfg.Provider, cfg.Issuer, c)
	if r != nil {
		return cirun.PipelineKey{}, &PreviewRefusal{Code: r.Code, Detail: r.Detail}
	}
	return key, nil
}

func errPreviewWrap(err error) error {
	return fmt.Errorf("%w: %v", shared.ErrValidation, err)
}

// unverifiedPayload decodes the sample's payload for display only.
func unverifiedPayload(raw string) (map[string]any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > oidc.MaxTokenSize {
		return nil, errPreviewToken
	}
	m, err := oidc.UnverifiedClaims(raw)
	if err != nil {
		return nil, errPreviewToken
	}
	for k := range m {
		if personalClaims[k] {
			delete(m, k)
		}
	}
	return m, nil
}

// previewError is the verification failure shown to the administrator: the
// verifier's message, which names the check that failed and never the token.
func previewError(err error) string {
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}
