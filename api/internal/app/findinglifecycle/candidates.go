package findinglifecycle

import (
	"context"
	"fmt"
	"sync"

	lc "github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The published schemes the status paths evaluate. A published version
// never changes, so its compiled form is cached by version id; a new
// publish is a new id, so the cache needs no invalidation. Each call still
// reads which versions are published (one tenant-scoped query), so a
// publish or an archive takes effect on the next move.

const compiledCacheMax = 1024

type compiledCache struct {
	mu sync.Mutex
	m  map[shared.ID]*lc.Compiled
}

func (c *compiledCache) get(id shared.ID) (*lc.Compiled, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[id]
	return v, ok
}

func (c *compiledCache) put(id shared.ID, v *lc.Compiled) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= compiledCacheMax {
		c.m = make(map[shared.ID]*lc.Compiled, 64)
	}
	c.m[id] = v
}

// ErrPublishedInvalid: a published version no longer compiles. The move is
// refused rather than decided without the organization's rules.
var ErrPublishedInvalid = fmt.Errorf("%w: the organization's finding lifecycle could not be loaded", shared.ErrValidation)

// Candidates returns the tenant's published schemes, compiled, with their
// context selectors: what lc.SelectScheme picks from for each finding. None
// (nil) means the system lifecycle.
func (s *Service) Candidates(ctx context.Context, tenantID shared.ID) ([]lc.Candidate, error) {
	published, err := s.schemes.Published(ctx, tenantID, lc.ObjectKindFinding)
	if err != nil || len(published) == 0 {
		return nil, err
	}
	var refs []lc.SubStatusRef
	out := make([]lc.Candidate, 0, len(published))
	for _, p := range published {
		compiled, ok := s.compiled.get(p.Version.ID)
		if !ok || compiled.Meta().VersionID != p.Version.ID {
			if refs == nil {
				if refs, err = s.catalogRefs(ctx, tenantID); err != nil {
					return nil, err
				}
				// An archived sub-status a published version still uses
				// (never, archive refuses it) must not lock the lifecycle.
				for i := range refs {
					refs[i].Archived = false
				}
			}
			c, v := lc.Compile(p.Version.Spec, refs, lc.Meta{SchemeID: p.Scheme.ID(), VersionID: p.Version.ID, Version: p.Version.Number})
			if !v.OK() {
				s.logger.Error("published lifecycle does not compile", "tenant_id", tenantID.String(),
					"version_id", p.Version.ID.String(), "error", v.Err())
				return nil, ErrPublishedInvalid
			}
			s.compiled.put(p.Version.ID, c)
			compiled = c
		}
		cand := lc.Candidate{Scheme: compiled, Priority: p.Scheme.Priority(), Default: p.Scheme.IsDefault()}
		if !cand.Default {
			sel, v := lc.CompileContext(p.Scheme.Context())
			if !v.OK() {
				return nil, ErrPublishedInvalid
			}
			cand.Context = sel
		}
		out = append(out, cand)
	}
	return out, nil
}
