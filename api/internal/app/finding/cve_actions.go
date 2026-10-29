package finding

// Bulk actions from the vulnerabilities list and page
// (docs/architecture/vulnerability-page.md, "Bulk actions"). Each acts on the
// open findings of a selection of CVEs, as the caller: the list's findings
// filter compiled with the caller's tenant, data scope and visibility rules,
// narrowed to the selected CVEs. No new write path: an exception is a group
// exception (the approval policy decides it, per-organization approvers),
// a retest is the finding's own retest, an export is the findings export.
//
// Threat model: the CVE ids and the filter come from the client; they only
// narrow what the compiled filter already lets the caller see, so a forged
// CVE id or filter can never reach a finding of another tenant or outside
// the caller's scope. Sizes are capped (100 CVEs per request, 500 findings
// per exception, the export's row cap) and every action is audited.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// MaxCVESelection bounds the CVEs one bulk action names.
const MaxCVESelection = filterspec.MaxValues

// MaxCVEExportCVEs bounds the CVEs an export of the whole list covers (the
// rows of the list under its filters); more must be narrowed first.
const MaxCVEExportCVEs = 1000

// ErrCVESelection: the selection is empty, too large or names a malformed id.
var ErrCVESelection = fmt.Errorf("%w: select 1 to %d vulnerabilities by CVE id", shared.ErrValidation, MaxCVESelection)

// CVESelection is the target of a bulk action: the open findings of the
// selected CVEs that the list's findings filter selects for the caller.
type CVESelection struct {
	// CVEIDs are the selected CVEs (normalized by NormalizeCVESelection).
	CVEIDs []string
	// Spec is the list's findings filter (nil: none). Its own cve_id and
	// state conditions are replaced by the selection and the open lens.
	Spec *filterspec.Spec
}

// NormalizeCVESelection upper-cases, de-duplicates and validates CVE ids.
func NormalizeCVESelection(ids []string) ([]string, error) {
	if len(ids) == 0 || len(ids) > MaxCVESelection {
		return nil, ErrCVESelection
	}
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if !vulnPageCVEPattern.MatchString(id) {
			return nil, ErrCVESelection
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// cveSelectionSpec is the selection's findings filter: the list's filter
// with cve_id in the selection and, when openOnly, the open lens.
func cveSelectionSpec(sel CVESelection, openOnly bool) (*filterspec.Spec, error) {
	q := url.Values{"cve_id": {strings.Join(sel.CVEIDs, ",")}}
	if openOnly {
		q.Set("state", "open")
	}
	narrow, err := filterspec.ParseValues(q, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
	if err != nil {
		return nil, err
	}
	base := sel.Spec
	if base == nil {
		base = &filterspec.Spec{}
	}
	out, err := filterspec.Overlay(base, narrow)
	if err != nil {
		return nil, err
	}
	// Most urgent first: an action capped below the selection's size takes
	// the riskiest findings.
	out.Sort = []filterspec.SortKey{{Field: "priority_class"}, {Field: "severity", Desc: true}, {Field: "first_detected_at"}}
	return out, nil
}

// OpenFindingIDsOfCVEs returns up to limit open findings of the selection, as
// the caller (most urgent first), and how many there are in all.
func (s *VulnerabilityService) OpenFindingIDsOfCVEs(ctx context.Context, c FilterCaller, sel CVESelection, limit int) ([]shared.ID, int64, error) {
	ids, ok := s.findingRepo.(findingIDsRepo)
	counts, ok2 := s.findingRepo.(findingWhereRepo)
	if !ok || !ok2 {
		return nil, 0, errNoFindingWhereRepo
	}
	cves, err := NormalizeCVESelection(sel.CVEIDs)
	if err != nil {
		return nil, 0, err
	}
	sel.CVEIDs = cves
	spec, err := cveSelectionSpec(sel, true)
	if err != nil {
		return nil, 0, err
	}
	actor, err := s.FilterActor(ctx, c)
	if err != nil {
		return nil, 0, err
	}
	where, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFields, actor)
	if err != nil {
		return nil, 0, err
	}
	total, err := counts.CountWhere(ctx, where)
	if err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return nil, 0, nil
	}
	list, err := ids.IDsWhere(ctx, where, limit)
	return list, total, err
}

// CVEExceptionInput asks for one exception over the open findings of a
// selection of vulnerabilities.
type CVEExceptionInput struct {
	Caller          FilterCaller
	Selection       CVESelection
	RequestedStatus string
	ClosureReason   string
	Justification   string
	ExpiresAt       *time.Time
	RequestedBy     shared.ID
	// Guard, when set, is the bulk-size rail, called with the number of
	// findings before the request is created.
	Guard func(size int) error
	Audit audit.AuditContext
}

// ErrCVEExceptionTooLarge: the selection has more open findings than one
// exception may decide.
var ErrCVEExceptionTooLarge = fmt.Errorf("%w: one exception covers at most %d open findings; narrow the filters or select fewer vulnerabilities",
	shared.ErrValidation, vulnerability.MaxApprovalBatchMembers)

// ErrCVEExceptionEmpty: the selection has no open finding in the caller's scope.
var ErrCVEExceptionEmpty = fmt.Errorf("%w: the selected vulnerabilities have no open finding you can see", shared.ErrValidation)

func (s *VulnerabilityService) cveExceptionInput(ctx context.Context, in CVEExceptionInput) (GroupExceptionInput, error) {
	ids, total, err := s.OpenFindingIDsOfCVEs(ctx, in.Caller, in.Selection, vulnerability.MaxApprovalBatchMembers)
	if err != nil {
		return GroupExceptionInput{}, err
	}
	if total == 0 {
		return GroupExceptionInput{}, ErrCVEExceptionEmpty
	}
	if total > int64(vulnerability.MaxApprovalBatchMembers) {
		return GroupExceptionInput{}, ErrCVEExceptionTooLarge
	}
	tenantID, err := shared.IDFromString(in.Caller.TenantID)
	if err != nil {
		return GroupExceptionInput{}, fmt.Errorf("%w: tenant", shared.ErrValidation)
	}
	cves, _ := NormalizeCVESelection(in.Selection.CVEIDs)
	return GroupExceptionInput{
		TenantID: tenantID, SourceType: vulnerability.ApprovalBatchSourceVulnerabilities, SourceID: shared.NewID(),
		SourceLabel: cveSelectionLabel(cves), FindingIDs: ids,
		RequestedStatus: in.RequestedStatus, ClosureReason: in.ClosureReason, Justification: in.Justification,
		ExpiresAt: in.ExpiresAt, RequestedBy: in.RequestedBy,
	}, nil
}

// cveSelectionLabel names a selection in at most 200 characters: the CVE
// ids, then "+N".
func cveSelectionLabel(cves []string) string {
	var b strings.Builder
	for i, id := range cves {
		more := fmt.Sprintf(" +%d", len(cves)-i)
		sep := ""
		if i > 0 {
			sep = ", "
		}
		if b.Len()+len(sep)+len(id)+len(more) > 200 && i < len(cves)-1 || b.Len()+len(sep)+len(id) > 200 {
			b.WriteString(more)
			break
		}
		b.WriteString(sep + id)
	}
	return b.String()
}

// PreviewCVEException answers how an exception over the selection would be
// decided (the group tier, each finding with its own tier and end).
func (s *VulnerabilityService) PreviewCVEException(ctx context.Context, in CVEExceptionInput) (*GroupExceptionPreview, error) {
	gi, err := s.cveExceptionInput(ctx, in)
	if err != nil {
		return nil, err
	}
	return s.PreviewGroupException(ctx, gi)
}

// RequestCVEException creates the exception: one pending group decided by
// the organization's approval policy, then each finding carries its own
// decision. Audited.
func (s *VulnerabilityService) RequestCVEException(ctx context.Context, in CVEExceptionInput) (*GroupExceptionResult, error) {
	gi, err := s.cveExceptionInput(ctx, in)
	if err != nil {
		return nil, err
	}
	if in.Guard != nil {
		if err := in.Guard(len(gi.FindingIDs)); err != nil {
			return nil, err
		}
	}
	res, err := s.RequestGroupException(ctx, gi)
	if err != nil {
		return nil, err
	}
	if s.auditService != nil {
		ev := audit.NewSuccessEvent(auditdom.ActionVulnerabilityExceptionRequested, auditdom.ResourceTypeVulnerabilitySelection, res.Batch.ID.String()).
			WithResourceName(gi.SourceLabel).
			WithMessage(fmt.Sprintf("Exception requested on %s: %s for %d finding(s), tier %s",
				gi.SourceLabel, in.RequestedStatus, res.Batch.MemberCount, res.Batch.Tier)).
			WithMetadata("batch_id", res.Batch.ID.String()).
			WithMetadata("cve_ids", strings.Join(gi.cves(), ",")).
			WithMetadata("requested_status", in.RequestedStatus).
			WithMetadata("members", res.Batch.MemberCount).
			WithMetadata("tier", res.Batch.Tier).
			WithSeverity(auditdom.SeverityMedium)
		if aerr := s.auditService.LogEvent(ctx, in.Audit, ev); aerr != nil {
			s.logger.Warn("audit vulnerability exception failed", "error", aerr)
		}
	}
	return res, nil
}

// cves are the selection's CVE ids as the label names them.
func (gi GroupExceptionInput) cves() []string {
	return strings.Split(strings.Split(gi.SourceLabel, " +")[0], ", ")
}

// IsCVESelectionError reports a selection the caller must change (400).
func IsCVESelectionError(err error) bool {
	return errors.Is(err, ErrCVESelection) || errors.Is(err, ErrCVEExceptionTooLarge) || errors.Is(err, ErrCVEExceptionEmpty)
}

// AuditCVERetest records a bulk retest of a selection (each queued retest
// is audited on its own as well).
func (s *VulnerabilityService) AuditCVERetest(ctx context.Context, actx audit.AuditContext, cves []string, open int64, counts map[string]int) {
	if s.auditService == nil {
		return
	}
	label := cveSelectionLabel(cves)
	ev := audit.NewSuccessEvent(auditdom.ActionVulnerabilityRetestRequested, auditdom.ResourceTypeVulnerabilitySelection, label).
		WithResourceName(label).
		WithMessage(fmt.Sprintf("Retest requested for the open findings of %s: %d queued", label, counts["queued"])).
		WithMetadata("cve_ids", strings.Join(cves, ",")).
		WithMetadata("open_findings", open).
		WithMetadata("outcomes", counts).
		WithSeverity(auditdom.SeverityLow)
	if err := s.auditService.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Warn("audit vulnerability retest failed", "error", err)
	}
}

// ErrCVEExportTooLarge: the list has more rows than one export covers.
var ErrCVEExportTooLarge = fmt.Errorf("%w: the export covers at most %d vulnerabilities; narrow the filters or select rows",
	shared.ErrValidation, MaxCVEExportCVEs)

// CVEExportSpec is the findings filter of an export of the list: the list's
// findings filter, limited to findings with a CVE and, when a list-level
// filter (kev, exploit, has_fix, emerging, past_sla, epss_gte, q) narrows the
// rows, to the CVEs of the matching rows (at most MaxCVEExportCVEs). The
// export then compiles it as the caller like any findings export.
func (s *VulnerabilityService) CVEExportSpec(ctx context.Context, c FilterCaller, spec *filterspec.Spec, opts vulnerability.CVEListOptions) (*filterspec.Spec, error) {
	if spec == nil {
		spec = &filterspec.Spec{}
	}
	leaf := &filterspec.Leaf{Field: "cve_id", Op: filterspec.OpIsNull, Values: []any{false}}
	if opts.HasCVELevelFilter() {
		ids, err := s.matchingCVEIDs(ctx, c, spec, opts)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			// No row matches: an export with its header only.
			ids = []string{"CVE-0000-0000"}
		}
		vals := make([]any, len(ids))
		for i, id := range ids {
			vals[i] = id
		}
		leaf = &filterspec.Leaf{Field: "cve_id", Op: filterspec.OpIn, Values: vals}
	}
	out := *spec
	kids := []*filterspec.Node{{Leaf: leaf}}
	if spec.Root != nil {
		kids = append([]*filterspec.Node{spec.Root}, kids...)
	}
	out.Root = &filterspec.Node{All: kids}
	out.Page, out.PerPage = 0, 0
	return &out, nil
}

// matchingCVEIDs pages through the list's rows (as the caller) and returns
// their CVE ids; more than MaxCVEExportCVEs is ErrCVEExportTooLarge.
func (s *VulnerabilityService) matchingCVEIDs(ctx context.Context, c FilterCaller, spec *filterspec.Spec, opts vulnerability.CVEListOptions) ([]string, error) {
	const perPage = 100
	var ids []string
	for page := 1; ; page++ {
		o := opts
		o.Page, o.PerPage = page, perPage
		res, err := s.ListCVEExposures(ctx, c, spec, o)
		if err != nil {
			return nil, err
		}
		if res.Total > MaxCVEExportCVEs {
			return nil, ErrCVEExportTooLarge
		}
		for _, it := range res.Data {
			ids = append(ids, it.CVEID)
		}
		if len(res.Data) < perPage || int64(len(ids)) >= res.Total {
			return ids, nil
		}
	}
}
