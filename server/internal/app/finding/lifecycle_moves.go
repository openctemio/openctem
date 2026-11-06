package finding

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	lc "github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The organization's finding lifecycle on the status paths
// (docs/rfcs/RFC-110-tenant-lifecycles.md). The platform engine decides
// first; the scheme selected for the finding can only narrow that decision
// (findinglifecycle.EvaluateMove). A sub-status changes only here, as a
// decided move, and the move is kept on the timeline with the lifecycle
// version that decided it.

// LifecycleSchemes returns a tenant's published lifecycle schemes
// (*findinglifecycle app Service); none means the system lifecycle.
type LifecycleSchemes interface {
	Candidates(ctx context.Context, tenantID shared.ID) ([]lc.Candidate, error)
}

// SetLifecycles wires the organization lifecycles. Without it every move
// is decided by the platform alone and no sub-status can be set.
func (s *VulnerabilityService) SetLifecycles(l LifecycleSchemes) { s.lifecycles = l }

func (s *VulnerabilityService) lifecycleCandidates(ctx context.Context, tenantID shared.ID) ([]lc.Candidate, error) {
	if s.lifecycles == nil {
		return nil, nil
	}
	return s.lifecycles.Candidates(ctx, tenantID)
}

// lifecycleActor is the engine actor plus the finding permissions the
// caller holds, for require_permission guards. Delegated actors (a
// workflow, a ticket) hold no person's permissions.
func lifecycleActor(ctx context.Context, a vulnerability.TransitionActor) lc.Actor {
	out := lc.Actor{TransitionActor: a}
	if a.Kind == vulnerability.TransitionActorWorkflow || a.Kind == vulnerability.TransitionActorTicket {
		return out
	}
	for _, p := range lc.GuardPermissions() {
		if shared.CallerHasPermission(ctx, p) {
			out.Permissions = append(out.Permissions, p)
		}
	}
	return out
}

// lifecycleFacts is what the tenant layer reads about a finding.
func lifecycleFacts(f *vulnerability.Finding, facts vulnerability.TransitionFacts) lc.Facts {
	out := lc.Facts{
		TransitionFacts: facts, ClosureReason: f.ClosureReason(),
		FindingType: string(f.FindingType()), ToolName: f.ToolName(),
	}
	if id := f.SubStatusID(); id != nil {
		out.SubStatus = *id
	}
	return out
}

// lifecycleDecision decides moving f to target for actor under the scheme
// selected from cands (nil cands: the platform alone).
func lifecycleDecision(cands []lc.Candidate, f *vulnerability.Finding, facts vulnerability.TransitionFacts,
	a lc.Actor, target lc.Target,
) (lc.Decision, *lc.Compiled) {
	lf := lifecycleFacts(f, facts)
	scheme := lc.SelectScheme(cands, lf.ConditionFacts())
	return lc.EvaluateMove(scheme, lf, a, target), scheme
}

// ErrLifecycleMove is a move the organization's lifecycle refuses.
var ErrLifecycleMove = fmt.Errorf("%w: the organization's finding lifecycle does not allow this move", shared.ErrValidation)

// lifecycleError maps a narrowed decision to the error a path answers with:
// first the platform's own errors (transitionError), then the
// organization's blocks, the longer note and the required fields. It returns
// the cleaned field values when the move may go ahead.
func lifecycleError(d lc.Decision, note string, fields map[string]string) (map[string]string, error) {
	// The organization's blocks are reported before the platform's mode
	// errors so a request or a picker is never offered for a move the
	// lifecycle refuses anyway.
	for _, b := range d.Blocked {
		if msg, ok := lifecycleBlockMessage(b); ok {
			return nil, fmt.Errorf("%w: %s", ErrLifecycleMove, msg)
		}
	}
	if err := transitionError(d.TransitionDecision, note); err != nil {
		return nil, err
	}
	if d.NoteMinLen > 0 && utf8.RuneCountInString(strings.TrimSpace(note)) < d.NoteMinLen {
		return nil, fmt.Errorf("%w: this move needs a note of at least %d characters", shared.ErrValidation, d.NoteMinLen)
	}
	return lc.CheckFields(d.Fields, fields)
}

func lifecycleBlockMessage(b vulnerability.TransitionBlock) (string, bool) {
	switch b.Code {
	case lc.BlockNotInLifecycle:
		return "the move is not part of the lifecycle", true
	case lc.BlockSameSubStatus:
		return "the finding already has this sub-status", true
	case lc.BlockClosureReasonChange:
		return "the sub-status belongs to another closure reason", true
	case lc.BlockPlatformSubStatus:
		return "that sub-status is set by the platform only", true
	case lc.BlockLifecyclePermission:
		return "the move needs one of " + b.Params["any_of"], true
	case lc.BlockActorKindDenied:
		return "this kind of actor (" + b.Params["kind"] + ") may not make the move", true
	}
	return "", false
}

// parseSubStatus reads an optional sub-status id from a request.
func parseSubStatus(raw string) (shared.ID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return shared.ID{}, nil
	}
	id, err := shared.IDFromString(raw)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: sub_status_id is not a valid id", shared.ErrValidation)
	}
	return id, nil
}

// lifecycleVersionOf is the timeline's record of which rules decided a
// move: the scheme version, or the platform lifecycle.
func lifecycleVersionOf(scheme *lc.Compiled) string {
	if scheme == nil {
		return vulnerability.PlatformLifecycleVersion
	}
	return fmt.Sprintf("lifecycle:%s@%d", scheme.Meta().VersionID, scheme.Meta().Version)
}

func sameID(a, b *shared.ID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
