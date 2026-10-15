package cirun

// Re-exchange of a CI job's OIDC token and the refusals a job is told about
// (RFC-051).
//
// A job's OIDC token is exchanged once for a run and an upload token. The
// same token presented again, while it is valid, gets a fresh upload token
// for the same run, and nothing else:
//   - same issuer and jti, same exact bytes (SHA-256), same organization;
//   - the run is the one recorded for the token, with every check of a
//     continuation (repository, commit, pipeline run, attempt, job, still
//     running, within MaxRunContinuation);
//   - at most cirun.MaxTokenExchanges exchanges per token, each audited.
//
// Threat model: whoever holds a valid token can already exchange it once and
// upload to that run until the upload token expires. A re-exchange gives
// them the same run again and no other run, organization or scope, so it
// adds no capability; refusing it only broke honest jobs whose first answer
// was lost or that run openctem-ci more than once. A different token (other
// bytes under a used jti) is still a replay, refused and audited high.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// RefusedError is a refusal the job is told the reason for. It is used only
// once a trust configuration of the organization admitted the token: the
// caller is then the organization's own pipeline, and the message names
// only that pipeline's own token and run. A refusal before admission (bad
// signature, wrong audience, no rule matches) stays the generic one, so a
// stranger's token learns nothing about the organization's configuration.
type RefusedError struct {
	Code    string
	Message string
}

func (e *RefusedError) Error() string { return ErrExchangeRefused.Error() + ": " + e.Code }
func (e *RefusedError) Unwrap() error { return ErrExchangeRefused }

// publicRefusal is the message an admitted pipeline gets for a refusal. The
// audit detail may name what only an administrator should see (another
// repository id, a pinned owner id); this text does not.
func publicRefusal(r *cirun.Refusal) error {
	msg := map[string]string{
		RefuseRepositoryBinding: "This repository name already reports under another repository id; an administrator must retire the old CI pipeline first.",
		RefuseOwnerPin:          "This group or organization name is pinned to another id in the CI trust configuration; an administrator must update the configuration.",
		"legacy_audience":       "This pipeline already moved to the audience openctem:tenant:<organization id>; set that audience in the job's id_tokens.",
		"aggregate_no_run_id":   "The token names no pipeline run, so it cannot join an aggregate run.",
		"pipeline_rate":         fmt.Sprintf("This pipeline started %d or more runs in the last hour; wait and rerun.", cirun.MaxPipelineRunsPerHour),
		"pipeline_cap":          "The organization or the trust configuration has the most CI pipelines it may have; an administrator must retire one.",
	}[r.Code]
	if msg == "" {
		msg = r.Detail
	}
	return &RefusedError{Code: r.Code, Message: msg}
}

// refuseCreate audits and words the refusals of createRun.
func (s *Service) refuseCreate(ctx context.Context, tenantID shared.ID, in ExchangeInput, c cirun.Claims, err error) error {
	var r *cirun.Refusal
	switch {
	case errors.Is(err, errAggregateNoRunID):
		r = &cirun.Refusal{Code: "aggregate_no_run_id", Detail: "the token names no pipeline run, so it cannot join an aggregate run"}
	case errors.Is(err, errPipelineRate):
		r = &cirun.Refusal{Code: "pipeline_rate", Detail: fmt.Sprintf("the pipeline started %d or more runs in the last hour", cirun.MaxPipelineRunsPerHour)}
	case errors.Is(err, cirun.ErrPipelineCap):
		r = &cirun.Refusal{Code: "pipeline_cap", Detail: "the organization or the trust configuration has the most CI pipelines it may have"}
	default:
		return err
	}
	s.auditRefusal(ctx, tenantID, in, c, []*cirun.Refusal{r})
	return publicRefusal(r)
}

// reuseToken admits a second exchange of the same token, or refuses it.
func (s *Service) reuseToken(ctx context.Context, tenantID shared.ID, in ExchangeInput, c cirun.Claims,
	tok *oidc.WorkloadToken, digest []byte, prior *cirun.Replay) (*cirun.Replay, error) {
	same := prior != nil && prior.TenantID != nil && *prior.TenantID == tenantID && bytes.Equal(prior.TokenSHA256, digest)
	if !same {
		// Another token under a used jti, a token used in another
		// organization, or a record from before re-exchange: a replay.
		// Nothing of the earlier record is told.
		s.auditRefusal(ctx, tenantID, in, c, []*cirun.Refusal{{Code: "replay", Detail: "this token was exchanged before"}})
		return nil, &RefusedError{Code: "replay", Message: "This CI token was already exchanged and cannot be exchanged again; rerun the job for a new token."}
	}
	rp, err := s.repo.ReuseReplay(ctx, tok.Issuer, tok.JTI, tenantID, digest, cirun.MaxTokenExchanges)
	if err != nil {
		return nil, fmt.Errorf("record token reuse: %w", err)
	}
	if rp == nil {
		s.auditRefusal(ctx, tenantID, in, c, []*cirun.Refusal{{Code: "replay_limit",
			Detail: fmt.Sprintf("this token was exchanged %d times, the most allowed", cirun.MaxTokenExchanges)}})
		return nil, &RefusedError{Code: "replay_limit", Message: fmt.Sprintf(
			"This CI token was already exchanged %d times (first at %s%s), the most allowed; rerun the job for a new token.",
			cirun.MaxTokenExchanges, prior.FirstAt.UTC().Format(time.RFC3339), forRun(prior.RunID))}
	}
	if rid := strings.TrimSpace(in.RunID); rid != "" && rp.RunID != nil && rid != rp.RunID.String() {
		s.auditRefusal(ctx, tenantID, in, c, []*cirun.Refusal{{Code: "run_mismatch",
			Detail: "the token asked to continue another run than the one it opened"}})
		return nil, &RefusedError{Code: "run_mismatch", Message: fmt.Sprintf(
			"This CI token belongs to run %s; it cannot continue another run.", rp.RunID)}
	}
	return rp, nil
}

func forRun(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return ", run " + id.String()
}

// resumeRun issues a fresh upload token for the run a token already opened
// or joined. A plain run that was never written (its creation failed) is
// created now under the id chosen at the first exchange.
func (s *Service) resumeRun(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, c cirun.Claims,
	key cirun.PipelineKey, in ExchangeInput, runID shared.ID, prior *cirun.Replay) (*ExchangeOutput, error) {
	_, err := s.repo.GetRun(ctx, tenantID, runID)
	if errors.Is(err, cirun.ErrRunNotFound) || errors.Is(err, shared.ErrNotFound) {
		return s.createRun(ctx, tenantID, cfg, c, key, in.UserAgent, false, &runID)
	}
	if err != nil {
		return nil, fmt.Errorf("load run: %w", err)
	}
	out, err := s.continueRun(ctx, tenantID, cfg, c, runID.String(), true)
	if errors.Is(err, ErrExchangeRefused) {
		s.auditRefusal(ctx, tenantID, in, c, []*cirun.Refusal{{Code: "replay_run_closed",
			Detail: "the token's run no longer accepts results"}})
		return nil, &RefusedError{Code: "replay_run_closed", Message: fmt.Sprintf(
			"This CI token was exchanged at %s for run %s, which no longer accepts results (evaluated, ended or too old); rerun the job.",
			prior.FirstAt.UTC().Format(time.RFC3339), runID)}
	}
	return out, err
}
