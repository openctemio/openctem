package scope

// Program exclusions (RFC-065 B7): the out-of-scope items of the
// organization's bug-bounty programs. The authority check (scopeauth) reads
// them through the scope service so that program entries never cover a name
// a program lists as out of scope; the organization's own entries ignore
// them.

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProgramExclusionReader lists a tenant's program exclusions
// (*postgres.BountyProgramRepository).
type ProgramExclusionReader interface {
	Exclusions(ctx context.Context, tenantID shared.ID, programID *shared.ID) ([]bountyprogram.Exclusion, error)
}

// SetProgramExclusions wires the program exclusions. Without it program
// entries cover nothing (scopeauth fails closed).
func (s *Service) SetProgramExclusions(r ProgramExclusionReader) { s.programExcl = r }

// ListProgramExclusions implements scopeauth.ProgramExclusions.
func (s *Service) ListProgramExclusions(ctx context.Context, tenantID shared.ID) ([]bountyprogram.Exclusion, error) {
	if s.programExcl == nil {
		return nil, scopeauth.ErrProgramsNotWired
	}
	return s.programExcl.Exclusions(ctx, tenantID, nil)
}
