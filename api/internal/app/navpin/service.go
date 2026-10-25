// Package navpin serves a member's sidebar pins (research/236 C4): a page,
// a built-in findings quick view or a saved view, with a live count for the
// two views. A pin is a bookmark: a saved view is shown only while the
// member can still see it, and every count is computed as the member.
package navpin

import (
	"context"
	"fmt"
	"net/url"

	"github.com/openctemio/openctem/api/internal/app/finding"
	savedviewapp "github.com/openctemio/openctem/api/internal/app/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/navpin"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Views lists and reads the saved views a member can see.
type Views interface {
	List(ctx context.Context, c savedviewapp.Caller, page string) ([]*savedview.View, error)
	Spec(ctx context.Context, c savedviewapp.Caller, id shared.ID, page string) (*filterspec.Spec, *savedview.View, error)
}

// Counter counts findings for filters, as the caller.
type Counter interface {
	CountSpecs(ctx context.Context, c finding.FilterCaller, specs []*filterspec.Spec) ([]int64, error)
}

// Caller is the member whose pins are read or written.
type Caller struct {
	TenantID shared.ID
	UserID   shared.ID
	Has      func(permission string) bool
	Filter   finding.FilterCaller
	View     savedviewapp.Caller
	// IncludeInformational: whether the member's work views show
	// informational findings (it changes the quick views' params).
	IncludeInformational bool
}

// PinView is a pin as the sidebar shows it.
type PinView struct {
	Kind navpin.Kind
	Ref  string
	// Name of a saved view.
	Name string
	// Params of a quick view (the list query it opens).
	Params string
	// Count of a quick or saved view; nil for a page or when counting failed.
	Count *int64
}

// Service reads and writes pins.
type Service struct {
	repo    navpin.Repository
	views   Views
	counter Counter
	logger  *logger.Logger
}

// NewService creates a Service. views and counter may be nil (no view pins).
func NewService(repo navpin.Repository, views Views, counter Counter, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, views: views, counter: counter, logger: log.With("component", "navpin")}
}

func quickViews(include bool) map[string]string {
	out := map[string]string{}
	for _, v := range vulnerability.FindingQuickViews(include) {
		out[v.Key] = v.Params
	}
	return out
}

func (c Caller) canReadFindings() bool {
	return c.Has != nil && c.Has(permission.FindingsRead.String())
}

// List returns the member's pins as the sidebar shows them. A view pin the
// member can no longer read is left out (and stays stored, so it comes back
// if access does).
func (s *Service) List(ctx context.Context, c Caller) ([]PinView, error) {
	pins, err := s.repo.List(ctx, c.TenantID, c.UserID)
	if err != nil {
		return nil, err
	}
	return s.present(ctx, c, pins), nil
}

// Replace stores the member's pins in order. A quick or saved view pin needs
// findings:read, and a saved view must be one the member can see now.
func (s *Service) Replace(ctx context.Context, c Caller, pins []navpin.Pin) ([]PinView, error) {
	qv := quickViews(c.IncludeInformational)
	if err := navpin.Validate(pins, func(k string) bool { _, ok := qv[k]; return ok }); err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}
	var visible map[string]bool // loaded once, when a saved view is pinned
	for _, p := range pins {
		if p.Kind == navpin.KindPage {
			continue
		}
		if !c.canReadFindings() || s.views == nil {
			return nil, fmt.Errorf("%w: pinning a findings view needs findings:read", shared.ErrForbidden)
		}
		if p.Kind != navpin.KindSavedView {
			continue
		}
		if visible == nil {
			vs, err := s.views.List(ctx, c.View, savedview.PageFindings)
			if err != nil {
				return nil, err
			}
			visible = make(map[string]bool, len(vs))
			for _, v := range vs {
				visible[v.ID.String()] = true
			}
		}
		if !visible[p.Ref] {
			return nil, fmt.Errorf("%w: saved view not found", shared.ErrNotFound)
		}
	}
	if err := s.repo.Replace(ctx, c.TenantID, c.UserID, pins); err != nil {
		return nil, err
	}
	return s.present(ctx, c, pins), nil
}

// present turns stored pins into what the sidebar shows, with one count
// statement for every view pin together.
func (s *Service) present(ctx context.Context, c Caller, pins []navpin.Pin) []PinView {
	qv := quickViews(c.IncludeInformational)
	out := make([]PinView, 0, len(pins))
	var specs []*filterspec.Spec
	var countAt []int
	for _, p := range pins {
		pv := PinView{Kind: p.Kind, Ref: p.Ref}
		switch p.Kind {
		case navpin.KindPage:
			out = append(out, pv)
			continue
		case navpin.KindQuickView:
			params, ok := qv[p.Ref]
			if !ok || !c.canReadFindings() {
				continue
			}
			pv.Params = params
			if spec, err := parseParams(params); err == nil {
				specs = append(specs, spec)
				countAt = append(countAt, len(out))
			}
		case navpin.KindSavedView:
			if !c.canReadFindings() || s.views == nil {
				continue
			}
			id, err := shared.IDFromString(p.Ref)
			if err != nil {
				continue
			}
			spec, v, err := s.views.Spec(ctx, c.View, id, savedview.PageFindings)
			if err != nil {
				// Deleted, unshared or no longer valid: not shown.
				continue
			}
			pv.Name = v.Name
			specs = append(specs, spec)
			countAt = append(countAt, len(out))
		default:
			continue
		}
		out = append(out, pv)
	}
	if len(specs) > 0 && s.counter != nil {
		counts, err := s.counter.CountSpecs(ctx, c.Filter, specs)
		if err != nil {
			s.logger.Debug("count pinned views failed", "error", logger.SanitizeError(err))
		} else {
			for i, at := range countAt {
				if i < len(counts) {
					n := counts[i]
					out[at].Count = &n
				}
			}
		}
	}
	return out
}

func parseParams(params string) (*filterspec.Spec, error) {
	q, err := url.ParseQuery(params)
	if err != nil {
		return nil, err
	}
	return filterspec.ParseValues(q, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
}
