// Package savedview manages saved list views (UI style contract D15,
// research 17 R3, docs/rfcs/RFC-048-list-query-contract.md §3.6).
//
// Rules (owner decisions A1 and A5):
//   - a view is personal, or shared with one access group (a team) its owner
//     belongs to; members use it, only the owner edits or deletes it, others
//     duplicate it;
//   - a view stores an RFC-048 FilterDocument, validated against the page's
//     field registry on save and again every time it runs; never SQL, never
//     results;
//   - a view runs as the person using it: the caller's tenant, data scope and
//     visibility rules apply, so sharing a view shares a query, not rows;
//   - every read and write is tenant-bound; a view of another tenant, or one
//     the caller may not see, is not found.
package savedview

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records view changes.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx audit.AuditContext, event audit.AuditEvent) error
}

// PageConfig is what a page needs to validate its views.
type PageConfig struct {
	Registry *filterspec.Registry
	// Permission is the page's read permission; using or saving a view
	// needs it.
	Permission string
	// GroupBy are the page's group-by dimensions.
	GroupBy map[string]bool
	// Extra are the page's own query params a saved query may carry.
	Extra []string
}

// Caller is the request's caller.
type Caller struct {
	TenantID shared.ID
	UserID   shared.ID
	Has      func(permission string) bool
	Audit    audit.AuditContext
}

// Input is a view to create or update. Exactly one of Filter (a
// FilterDocument) or Query (flat GET params, the page URL) describes the
// filter.
type Input struct {
	Page        string
	Name        string
	Description string
	Filter      []byte
	Query       string
	GroupID     *shared.ID
	GroupBy     string
	Columns     []string
	Density     string
}

// Service manages saved views.
type Service struct {
	repo   savedview.Repository
	pages  map[string]PageConfig
	audit  AuditLogger
	logger *logger.Logger
	now    func() time.Time
}

// NewService creates a Service.
func NewService(repo savedview.Repository, pages map[string]PageConfig, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, pages: pages, logger: log.With("component", "savedview"), now: time.Now}
}

// SetAuditService wires the audit trail.
func (s *Service) SetAuditService(a AuditLogger) { s.audit = a }

var (
	columnRE  = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	densityRE = regexp.MustCompile(`^[a-z]{1,16}$`)
)

func (s *Service) page(c Caller, page string) (PageConfig, error) {
	cfg, ok := s.pages[page]
	if !ok {
		return PageConfig{}, savedview.ErrUnknownPage
	}
	if cfg.Permission != "" && (c.Has == nil || !c.Has(cfg.Permission)) {
		// The caller cannot read the page: its views do not exist for them.
		return PageConfig{}, savedview.ErrNotFound
	}
	return cfg, nil
}

// List returns the views of a page the caller may see.
func (s *Service) List(ctx context.Context, c Caller, page string) ([]*savedview.View, error) {
	if _, err := s.page(c, page); err != nil {
		return nil, err
	}
	return s.repo.ListVisible(ctx, c.TenantID, c.UserID, page)
}

// Get returns a view the caller may see.
func (s *Service) Get(ctx context.Context, c Caller, id shared.ID) (*savedview.View, error) {
	v, err := s.repo.GetVisible(ctx, c.TenantID, id, c.UserID)
	if err != nil {
		return nil, err
	}
	if _, err := s.page(c, v.Page); err != nil {
		return nil, savedview.ErrNotFound
	}
	return v, nil
}

// Spec returns a view's filter, re-validated against the page registry now
// (the registry may have changed since the view was saved). It is the input
// of a list, stats, groups or export request, which compiles it as the caller.
func (s *Service) Spec(ctx context.Context, c Caller, id shared.ID, page string) (*filterspec.Spec, *savedview.View, error) {
	v, err := s.Get(ctx, c, id)
	if err != nil {
		return nil, nil, err
	}
	if v.Page != page {
		return nil, nil, savedview.ErrNotFound
	}
	cfg := s.pages[page]
	spec, err := filterspec.ParseDocument(v.Filter, cfg.Registry, filterspec.Options{Unknown: filterspec.UnknownStrict})
	if err != nil {
		return nil, nil, fmt.Errorf("the saved view's filter is no longer valid: %w", err)
	}
	return spec, v, nil
}

// Create saves a new view owned by the caller.
func (s *Service) Create(ctx context.Context, c Caller, in Input) (*savedview.View, error) {
	cfg, err := s.page(c, in.Page)
	if err != nil {
		return nil, err
	}
	v := &savedview.View{ID: shared.NewID(), TenantID: c.TenantID, OwnerID: c.UserID, Page: in.Page}
	if err := s.apply(ctx, c, cfg, v, in); err != nil {
		return nil, err
	}
	n, err := s.repo.CountByOwner(ctx, c.TenantID, c.UserID)
	if err != nil {
		return nil, err
	}
	if n >= savedview.MaxPerOwner {
		return nil, fmt.Errorf("%w: at most %d per person", savedview.ErrLimit, savedview.MaxPerOwner)
	}
	v.CreatedAt = s.now().UTC()
	v.UpdatedAt = v.CreatedAt
	if err := s.repo.Create(ctx, v); err != nil {
		return nil, err
	}
	s.log(ctx, c, auditdom.ActionSavedViewCreated, v)
	return s.repo.GetVisible(ctx, c.TenantID, v.ID, c.UserID)
}

// Update changes a view the caller owns (decision A1). A shared view the
// caller does not own is ErrNotOwner; a view they cannot see is ErrNotFound.
func (s *Service) Update(ctx context.Context, c Caller, id shared.ID, in Input) (*savedview.View, error) {
	v, err := s.Get(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if v.OwnerID != c.UserID {
		return nil, savedview.ErrNotOwner
	}
	in.Page = v.Page
	cfg := s.pages[v.Page]
	if err := s.apply(ctx, c, cfg, v, in); err != nil {
		return nil, err
	}
	v.UpdatedAt = s.now().UTC()
	if err := s.repo.Update(ctx, v); err != nil {
		return nil, err
	}
	s.log(ctx, c, auditdom.ActionSavedViewUpdated, v)
	return s.repo.GetVisible(ctx, c.TenantID, v.ID, c.UserID)
}

// Delete removes a view the caller owns.
func (s *Service) Delete(ctx context.Context, c Caller, id shared.ID) error {
	v, err := s.Get(ctx, c, id)
	if err != nil {
		return err
	}
	if v.OwnerID != c.UserID {
		return savedview.ErrNotOwner
	}
	if err := s.repo.Delete(ctx, c.TenantID, id, c.UserID); err != nil {
		return err
	}
	s.log(ctx, c, auditdom.ActionSavedViewDeleted, v)
	return nil
}

// Duplicate copies a view the caller may see into a new personal view they
// own (how a team member changes a shared view, decision A1).
func (s *Service) Duplicate(ctx context.Context, c Caller, id shared.ID, name string) (*savedview.View, error) {
	v, err := s.Get(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(name) == "" {
		name = "Copy of " + v.Name
	}
	if r := []rune(name); len(r) > savedview.MaxNameLen {
		name = string(r[:savedview.MaxNameLen])
	}
	return s.Create(ctx, c, Input{Page: v.Page, Name: name, Description: v.Description, Filter: v.Filter,
		GroupBy: v.GroupBy, Columns: v.Columns, Density: v.Density})
}

// apply validates in and writes it onto v.
func (s *Service) apply(ctx context.Context, c Caller, cfg PageConfig, v *savedview.View, in Input) error {
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > savedview.MaxNameLen || strings.ContainsFunc(name, unicode.IsControl) {
		return fmt.Errorf("%w: name must be 1-%d characters without control characters", savedview.ErrInvalid, savedview.MaxNameLen)
	}
	desc := strings.TrimSpace(in.Description)
	if utf8.RuneCountInString(desc) > savedview.MaxDescriptionLen || strings.ContainsFunc(desc, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }) {
		return fmt.Errorf("%w: description must be at most %d characters", savedview.ErrInvalid, savedview.MaxDescriptionLen)
	}
	doc, err := s.document(ctx, c, in.Page, cfg, in)
	if err != nil {
		return err
	}
	if in.GroupBy != "" && !cfg.GroupBy[in.GroupBy] {
		return fmt.Errorf("%w: unknown group_by", savedview.ErrInvalid)
	}
	if len(in.Columns) > savedview.MaxColumns {
		return fmt.Errorf("%w: at most %d columns", savedview.ErrInvalid, savedview.MaxColumns)
	}
	for _, col := range in.Columns {
		if !columnRE.MatchString(col) {
			return fmt.Errorf("%w: invalid column name", savedview.ErrInvalid)
		}
	}
	if in.Density != "" && !densityRE.MatchString(in.Density) {
		return fmt.Errorf("%w: invalid density", savedview.ErrInvalid)
	}
	if in.GroupID != nil {
		if err := s.checkShare(ctx, c, *in.GroupID, v); err != nil {
			return err
		}
	}
	v.Name, v.Description, v.Filter = name, desc, doc
	v.GroupID, v.GroupBy, v.Columns, v.Density = in.GroupID, in.GroupBy, in.Columns, in.Density
	return nil
}

// document validates the filter (document or flat query) against the page
// registry and returns the FilterDocument to store. A query that names a
// saved view the caller may see (view=<id>) saves that view's filter with the
// query's params on top, as the list would run it.
func (s *Service) document(ctx context.Context, c Caller, page string, cfg PageConfig, in Input) ([]byte, error) {
	opts := filterspec.Options{Unknown: filterspec.UnknownStrict, Extra: append([]string{"view"}, cfg.Extra...)}
	switch {
	case len(in.Filter) > 0 && in.Query != "":
		return nil, fmt.Errorf("%w: send filter or query, not both", savedview.ErrInvalid)
	case in.Query != "":
		if len(in.Query) > filterspec.MaxBodyBytes {
			return nil, fmt.Errorf("%w: query too long", savedview.ErrInvalid)
		}
		q, err := url.ParseQuery(in.Query)
		if err != nil {
			return nil, fmt.Errorf("%w: query is not a URL query string", savedview.ErrInvalid)
		}
		base := q.Get("view")
		for _, p := range []string{"page", "per_page", "view", "cursor"} {
			q.Del(p)
		}
		spec, err := filterspec.ParseValues(q, cfg.Registry, opts)
		if err != nil {
			return nil, err
		}
		if base != "" {
			id, err := shared.IDFromString(base)
			if err != nil {
				return nil, savedview.ErrNotFound
			}
			stored, _, err := s.Spec(ctx, c, id, page)
			if err != nil {
				return nil, err
			}
			if spec, err = filterspec.Overlay(stored, spec); err != nil {
				return nil, err
			}
		}
		return spec.DocumentJSON()
	default:
		raw := in.Filter
		if len(raw) == 0 {
			raw = []byte(`{}`)
		}
		spec, err := filterspec.ParseDocument(raw, cfg.Registry, opts)
		if err != nil {
			return nil, err
		}
		return spec.DocumentJSON()
	}
}

// checkShare allows sharing with an active group of the tenant that the
// caller belongs to. A group of another tenant or one the caller is not in
// is not found (no oracle), and a full group is ErrLimit.
func (s *Service) checkShare(ctx context.Context, c Caller, groupID shared.ID, v *savedview.View) error {
	ok, err := s.repo.IsActiveGroupMember(ctx, c.TenantID, groupID, c.UserID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: group not found", savedview.ErrInvalid)
	}
	if v.GroupID != nil && *v.GroupID == groupID {
		return nil // already shared there
	}
	n, err := s.repo.CountByGroup(ctx, c.TenantID, groupID)
	if err != nil {
		return err
	}
	if n >= savedview.MaxPerGroup {
		return fmt.Errorf("%w: at most %d per group", savedview.ErrLimit, savedview.MaxPerGroup)
	}
	return nil
}

func (s *Service) log(ctx context.Context, c Caller, action auditdom.Action, v *savedview.View) {
	if s.audit == nil {
		return
	}
	ev := audit.NewSuccessEvent(action, auditdom.ResourceTypeSavedView, v.ID.String()).
		WithResourceName(v.Name).
		WithMetadata("page", v.Page).
		WithMetadata("shared", v.GroupID != nil).
		WithSeverity(auditdom.SeverityLow)
	if v.GroupID != nil {
		ev = ev.WithMetadata("group_id", v.GroupID.String())
	}
	if err := s.audit.LogEvent(ctx, c.Audit, ev); err != nil {
		s.logger.Warn("audit saved view failed", "error", err)
	}
}

// IsNotFound reports whether err means "no such view for this caller".
func IsNotFound(err error) bool { return errors.Is(err, savedview.ErrNotFound) }
