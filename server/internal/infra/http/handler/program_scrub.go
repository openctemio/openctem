package handler

import (
	"context"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProgramReader returns which private programs the caller may read the
// names of (bountyprogram.Service.ReadablePrograms).
type ProgramReader interface {
	ReadablePrograms(ctx context.Context, tenantID, actor shared.ID, ids []shared.ID) (map[shared.ID]bool, error)
}

// programScrubber is the one rule for showing an event about private program
// assets to an integration admin (RFC-065 §15.4): names, handles and tags of
// programs the caller is neither an owner nor a member of are removed. Both
// collaborators nil shows everything unchanged.
type programScrubber struct {
	delivery bp.DeliveryResolver
	readable ProgramReader
}

// SetProgramScrub wires the private program resolver and reader. Both or
// neither.
func (p *programScrubber) SetProgramScrub(d bp.DeliveryResolver, r ProgramReader) {
	p.delivery, p.readable = d, r
}

// unreadable resolves the private programs linked to subject. ok is true
// when some of them are hidden from the caller; allowed holds the ones the
// caller may read. An unknown decision is an error: the caller answers 500
// rather than show the event.
func (p *programScrubber) unreadable(ctx context.Context, tenantID shared.ID, subject bp.DeliverySubject) (d bp.Delivery, allowed map[shared.ID]bool, ok bool, err error) {
	if p.delivery == nil || p.readable == nil {
		return d, nil, false, nil
	}
	actor, _ := shared.IDFromString(middleware.GetUserID(ctx))
	d, err = p.delivery.Resolve(ctx, tenantID, subject)
	if err != nil || len(d.Programs) == 0 {
		return d, nil, false, err
	}
	ids := make([]shared.ID, 0, len(d.Programs))
	for _, pr := range d.Programs {
		ids = append(ids, pr.ID)
	}
	allowed, err = p.readable.ReadablePrograms(ctx, tenantID, actor, ids)
	if err != nil {
		return d, nil, false, err
	}
	return d, allowed, len(allowed) != len(ids), nil
}

// scrubValue returns a copy of a decoded JSON value with every string
// scrubbed (the stored metadata is never modified).
func scrubValue(d bp.Delivery, allowed map[shared.ID]bool, v any) any {
	switch t := v.(type) {
	case string:
		return d.ScrubFor(allowed, t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = scrubValue(d, allowed, x)
		}
		return out
	case []map[string]any:
		out := make([]any, 0, len(t))
		for _, x := range t {
			out = append(out, scrubValue(d, allowed, x))
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, x := range t {
			out = append(out, scrubValue(d, allowed, x))
		}
		return out
	case []string:
		out := make([]any, 0, len(t))
		for _, x := range t {
			out = append(out, d.ScrubFor(allowed, x))
		}
		return out
	default:
		return v
	}
}
