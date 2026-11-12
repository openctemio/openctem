package bountyprogram

// Who may see a program, and the per-person attestation of a private one
// (RFC-065 §15.3).
//
// A public program is visible to its members and to full-data callers. A
// private program is visible only to its members and the organization's
// owners: administrators and full-data roles who are not members get "not
// found", like a caller from another tenant. Seeing a private program's
// details (scope, rules, link, sync, pending terms) also needs the caller's
// own acceptance of its current terms: until then the program shows only its
// name, platform and terms text. A change of terms asks everyone again.

import (
	"context"
	"fmt"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OwnerCheck answers whether the request's caller is an owner of the
// tenant (middleware.IsOwner).
type OwnerCheck func(ctx context.Context) bool

// SetOwnerCheck wires the owner check. Without it no caller is an owner
// (fail closed: private programs are then visible to members only).
func (s *Service) SetOwnerCheck(f OwnerCheck) { s.isOwner = f }

func (s *Service) ownerCaller(ctx context.Context) bool {
	return s.isOwner != nil && s.isOwner(ctx)
}

// canSee decides whether the caller may see p at all.
func (s *Service) canSee(ctx context.Context, p *bp.Program, actor shared.ID) (bool, error) {
	if p.IsPrivate() {
		if s.ownerCaller(ctx) {
			return true, nil
		}
	} else {
		full, err := s.isFullData(ctx, p.TenantID)
		if err != nil || full {
			return full, err
		}
	}
	if actor.IsZero() {
		return false, nil
	}
	return s.repo.IsMember(ctx, p.TenantID, p.ID, actor)
}

// attested reports whether actor accepted p's current terms; a public
// program needs no personal attestation.
func (s *Service) attested(ctx context.Context, p *bp.Program, actor shared.ID) (bool, error) {
	if !p.IsPrivate() {
		return true, nil
	}
	if actor.IsZero() {
		return false, nil
	}
	got, err := s.repo.Attestations(ctx, p.TenantID, actor)
	if err != nil {
		return false, err
	}
	return got[p.ID] != "" && got[p.ID] == p.TermsSHA256, nil
}

// loadAttested is loadForCaller for the program's details: a private
// program also needs the caller's attestation of its current terms.
func (s *Service) loadAttested(ctx context.Context, tenantID, actor, id shared.ID) (*bp.Program, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	ok, err := s.attested(ctx, p, actor)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, bp.ErrAttestationRequired
	}
	return p, nil
}

// recordAttestation stores the person's acceptance of p's current terms.
// Best effort after the change it belongs to: without it the person is
// asked again.
func (s *Service) recordAttestation(ctx context.Context, p *bp.Program, actor shared.ID) {
	if actor.IsZero() {
		return
	}
	if err := s.repo.Attest(ctx, bp.Attestation{TenantID: p.TenantID, ProgramID: p.ID, UserID: actor,
		TermsSHA256: p.TermsSHA256, AcceptedAt: s.now()}); err != nil {
		s.log.Warn("program attestation not recorded", "program_id", p.ID.String(), "error", err)
	}
}

// Attest records the caller's acceptance of a program's current terms and
// confidentiality (acceptTerms must be its terms_sha256). It changes no
// authorization: entries stay as they are.
func (s *Service) Attest(ctx context.Context, tenantID, actor, id shared.ID, acceptTerms string) (*bp.Program, error) {
	if actor.IsZero() {
		return nil, fmt.Errorf("%w: a person accepts a program's terms", shared.ErrForbidden)
	}
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	if err := checkTerms(acceptTerms, p.TermsSHA256); err != nil {
		return nil, err
	}
	if err := s.repo.Attest(ctx, bp.Attestation{TenantID: tenantID, ProgramID: id, UserID: actor,
		TermsSHA256: p.TermsSHA256, AcceptedAt: s.now()}); err != nil {
		return nil, err
	}
	return p, nil
}

// View is a program as a caller sees it in a list: Locked when it is
// private and the caller has not accepted its current terms (only the
// name, platform, visibility and terms are shown then).
type View struct {
	Program *bp.Program
	Locked  bool
}

// HiddenProgramIDs lists the tenant's private programs whose entries the
// caller may not see in the general scope views: every private program the
// caller cannot see or has not accepted the current terms of.
func (s *Service) HiddenProgramIDs(ctx context.Context, tenantID, actor shared.ID) ([]shared.ID, error) {
	private, err := s.repo.PrivateProgramIDs(ctx, tenantID)
	if err != nil || len(private) == 0 {
		return nil, err
	}
	var attested map[shared.ID]string
	member := map[shared.ID]bool{}
	if !actor.IsZero() {
		if attested, err = s.repo.Attestations(ctx, tenantID, actor); err != nil {
			return nil, err
		}
		ids, err := s.repo.MemberProgramIDs(ctx, tenantID, actor)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			member[id] = true
		}
	}
	owner := s.ownerCaller(ctx)
	hidden := make([]shared.ID, 0, len(private))
	for _, id := range private {
		if (owner || member[id]) && attested[id] != "" {
			p, err := s.repo.GetByID(ctx, tenantID, id)
			if err != nil {
				return nil, err
			}
			if attested[id] == p.TermsSHA256 {
				continue
			}
		}
		hidden = append(hidden, id)
	}
	return hidden, nil
}

// redact keeps what a person sees before accepting a private program's
// terms.
func redact(p *bp.Program) *bp.Program {
	return &bp.Program{ID: p.ID, TenantID: p.TenantID, Name: p.Name, Platform: p.Platform,
		Visibility: p.Visibility, TermsText: p.TermsText, Status: p.Status, ScopeSource: p.ScopeSource,
		TermsSHA256: p.TermsSHA256, GroupID: p.GroupID, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}
