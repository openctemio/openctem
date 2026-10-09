package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/dpop"
)

// DPoP sender-constrained tokens (RFC 9449, RFC-062 §9). A client that sends
// a DPoP proof to the token endpoint gets a grant bound to its key: every
// later token request and every MCP request of that grant must carry a fresh
// proof signed by the same key, so a copied token is useless on its own.

// ReplayCache remembers proof ids so a proof is accepted once (Redis SETNX).
type ReplayCache interface {
	// FirstUse reports whether key was not seen before, recording it for ttl.
	FirstUse(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// DPoPRequest is how an MCP request presented its access token.
type DPoPRequest struct {
	// Scheme is the Authorization scheme: "Bearer" or "DPoP".
	Scheme string
	// Proof is the DPoP header (empty when none).
	Proof  string
	Method string
}

// ErrDPoP is an access token refused for its DPoP proof (the resource
// server answers with a DPoP challenge).
var ErrDPoP = errors.New("invalid DPoP proof")

// DPoPAlgorithms are the proof algorithms accepted (metadata).
func DPoPAlgorithms() []string { return append([]string(nil), dpop.Algorithms...) }

// verifyDPoP verifies a proof and records its id. Without a replay cache no
// proof is accepted (fail closed).
func (s *Service) verifyDPoP(ctx context.Context, proof string, e dpop.Expect) (*dpop.Proof, error) {
	p, err := dpop.Verify(proof, e)
	if err != nil {
		return nil, err
	}
	if s.replay == nil {
		return nil, fmt.Errorf("%w: replay cache unavailable", dpop.ErrInvalidProof)
	}
	fresh, err := s.replay.FirstUse(ctx, "mcp:dpop:"+p.JKT+":"+p.JTI, dpop.ReplayWindow)
	if err != nil {
		return nil, fmt.Errorf("%w: replay cache: %v", dpop.ErrInvalidProof, err)
	}
	if !fresh {
		return nil, fmt.Errorf("%w: proof replayed", dpop.ErrInvalidProof)
	}
	return p, nil
}

// tokenProof verifies the DPoP proof of a token request, if any, and
// returns the key thumbprint ("" without a proof).
func (s *Service) tokenProof(ctx context.Context, proof string) (string, *OAuthError) {
	if proof == "" {
		return "", nil
	}
	p, err := s.verifyDPoP(ctx, proof, dpop.Expect{Method: "POST", URL: s.endpoints.Issuer + "/oauth/token", Now: s.now()})
	if err != nil {
		s.log.Debug("mcp oauth: token request DPoP proof refused", "reason", oneLine(err.Error()))
		return "", oauthErr("invalid_dpop_proof", "the DPoP proof is invalid")
	}
	return p.JKT, nil
}
