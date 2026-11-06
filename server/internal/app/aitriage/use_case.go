package aitriage

// The organization's setting of the triage AI use case
// (docs/architecture/ai-use-cases.md) applied to AI triage: off refuses every
// path (request, bulk, automatic, the worker before the call); the data class
// ceiling decides which finding fields reach the model; only auto-apply, at
// or above the minimum confidence, lets a verdict file a false-positive
// request on its own (a person still decides it).

import (
	"context"
	"errors"

	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrUseCaseOff: the organization turned the triage AI use case off.
var ErrUseCaseOff = errors.New("the triage AI use case is turned off for this organization")

// UseCaseSettings reads an organization's setting of one AI use case
// (tenantai.Service).
type UseCaseSettings interface {
	UseCaseSetting(ctx context.Context, tenantID shared.ID, uc aidom.UseCase) (aidom.UseCaseSetting, error)
}

// SetUseCases wires the per-use-case settings (nil: the default, suggest).
func (s *AITriageService) SetUseCases(u UseCaseSettings) { s.useCases = u }

// triageSetting returns the organization's triage use case setting; without
// a source the default (suggest, internal, 0.85).
func (s *AITriageService) triageSetting(ctx context.Context, tenantID shared.ID) (aidom.UseCaseSetting, error) {
	if s.useCases == nil {
		return aidom.DefaultUseCaseSetting(), nil
	}
	return s.useCases.UseCaseSetting(ctx, tenantID, aidom.UseCaseTriage)
}

// requireTriageOn refuses a request while the triage use case is off.
func (s *AITriageService) requireTriageOn(ctx context.Context, tenantID shared.ID) error {
	set, err := s.triageSetting(ctx, tenantID)
	if err != nil {
		return err
	}
	if set.Mode == aidom.UseCaseOff {
		return ErrUseCaseOff
	}
	return nil
}
