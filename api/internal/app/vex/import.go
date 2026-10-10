package vex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	vexdom "github.com/openctemio/openctem/api/pkg/domain/vex"
)

// Import limits. A VEX document is small; these refuse hostile input early.
const (
	// MaxDocumentBytes is the largest document accepted.
	MaxDocumentBytes = 5 << 20
	// MaxDocumentStatements is the most statements one document may make
	// after expanding products.
	MaxDocumentStatements = 5000
	maxListedSkips        = 100
	maxListedIssues       = 50
	maxListedItems        = 200
)

// ImportFormats are the document formats an import accepts.
var ImportFormats = []importer.Format{importer.FormatOpenVEX, importer.FormatCSAF, importer.FormatCycloneDX}

// ErrNoStatements refuses a document that holds no VEX statement.
var ErrNoStatements = fmt.Errorf("%w: the document holds no VEX statements (OpenVEX, CSAF VEX or CycloneDX VEX)", shared.ErrValidation)

// ImportItem is one statement an import makes.
type ImportItem struct {
	VulnID        string   `json:"vuln_id"`
	PURL          string   `json:"purl"`
	ProductID     string   `json:"product_id"`
	Versions      []string `json:"versions"`
	Status        string   `json:"status"`
	Justification string   `json:"justification,omitempty"`
	// Action is create, update or unchanged.
	Action string `json:"action"`
}

// ImportSkip is a statement of the document the import leaves out.
type ImportSkip struct {
	VulnID string `json:"vuln_id,omitempty"`
	PURL   string `json:"purl,omitempty"`
	Reason string `json:"reason"`
}

// ImportResult is what an import did, or in a preview would do.
type ImportResult struct {
	Format       string       `json:"format"`
	DryRun       bool         `json:"dry_run"`
	Statements   int          `json:"statements"`
	Created      int          `json:"created"`
	Updated      int          `json:"updated"`
	Unchanged    int          `json:"unchanged"`
	SkippedTotal int          `json:"skipped_total"`
	Skipped      []ImportSkip `json:"skipped"`
	Issues       []string     `json:"issues"`
	Items        []ImportItem `json:"items"`
	Applied      ApplyResult  `json:"applied"`
}

func (r *ImportResult) skip(s ImportSkip) {
	r.SkippedTotal++
	if len(r.Skipped) < maxListedSkips {
		r.Skipped = append(r.Skipped, s)
	}
}

// plannedStatement is a statement of the document before product
// resolution.
type plannedStatement struct {
	vulnID string
	purl   software.PURL
	raw    string
	vex    ctis.VEX
}

// ParseDocument reads a VEX document with strict limits: JSON formats only
// (OpenVEX, CSAF, CycloneDX), at most MaxDocumentBytes, at most
// MaxDocumentStatements statements.
func ParseDocument(ctx context.Context, r io.Reader) (*importer.Result, error) {
	lr := &io.LimitedReader{R: r, N: MaxDocumentBytes + 1}
	res, err := importer.Parse(ctx, lr, importer.Options{Limits: importer.Limits{
		MaxInputBytes: MaxDocumentBytes, MaxStatements: MaxDocumentStatements,
		MaxFindings: MaxDocumentStatements, MaxComponents: 100_000, MaxAssets: 1000, MaxIssues: maxListedIssues,
	}})
	if lr.N <= 0 {
		return nil, fmt.Errorf("%w: the document is larger than %d MB", shared.ErrValidation, MaxDocumentBytes>>20)
	}
	if err != nil {
		var pe *importer.ParseError
		if errors.As(err, &pe) {
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, pe.Error())
		}
		return nil, fmt.Errorf("%w: the document could not be read", shared.ErrValidation)
	}
	if !slices.Contains(ImportFormats, res.Format) {
		return nil, fmt.Errorf("%w: %s is not a VEX format; use OpenVEX, CSAF VEX or CycloneDX VEX", shared.ErrValidation, res.Format)
	}
	if len(res.VEX) == 0 {
		return nil, ErrNoStatements
	}
	return res, nil
}

// planDocument expands the document's statements into one statement per
// vulnerability and package. A statement about components inside a
// product (subcomponents) is kept only when the import targets an asset;
// a product named without a package URL cannot be matched to the
// inventory.
func planDocument(res *importer.Result, assetBound bool, out *ImportResult) []plannedStatement {
	var plan []plannedStatement
	for i := range res.VEX {
		st := &res.VEX[i]
		vulnID, err := primaryVulnID(st.VulnerabilityIDs)
		if err != nil {
			out.skip(ImportSkip{Reason: "no usable vulnerability id"})
			continue
		}
		for _, p := range st.Products {
			targets := []importer.Product{p}
			if len(p.Subcomponents) > 0 {
				if !assetBound {
					out.skip(ImportSkip{VulnID: vulnID, PURL: p.PURL, Reason: "statement about components inside a product: choose the target asset"})
					continue
				}
				targets = p.Subcomponents
			}
			for _, t := range targets {
				if t.PURL == "" {
					out.skip(ImportSkip{VulnID: vulnID, Reason: "product has no package URL"})
					continue
				}
				pu, err := software.ParsePURL(t.PURL)
				if err != nil {
					out.skip(ImportSkip{VulnID: vulnID, PURL: truncate(t.PURL, 200), Reason: "invalid package URL"})
					continue
				}
				if len(plan) >= MaxDocumentStatements {
					out.skip(ImportSkip{VulnID: vulnID, PURL: truncate(t.PURL, 200), Reason: "too many statements in one document"})
					continue
				}
				plan = append(plan, plannedStatement{vulnID: vulnID, purl: pu, raw: truncate(t.PURL, 600), vex: st.VEX})
			}
		}
	}
	return plan
}

// primaryVulnID is the statement's CVE when it has one, else its first id.
func primaryVulnID(ids []ctis.VulnerabilityID) (string, error) {
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id.ID)), "CVE-") {
			return vexdom.NormalizeVulnID(id.ID)
		}
	}
	for _, id := range ids {
		if v, err := vexdom.NormalizeVulnID(id.ID); err == nil {
			return v, nil
		}
	}
	return "", errors.New("no id")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Import reads a VEX document and stores its statements (origin document),
// for assetID or, empty, for every asset; then applies them. With dryRun it
// reports what it would do and writes nothing. A statement the
// organization wrote by hand for the same subject is never overwritten.
func (s *Service) Import(ctx context.Context, tenantID shared.ID, assetID string, r io.Reader, dryRun bool,
	actx auditapp.AuditContext) (*ImportResult, error) {
	aid, err := parseOptionalID(assetID, "asset_id")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeSubject(ctx, tenantID, aid); err != nil {
		return nil, err
	}
	doc, err := ParseDocument(ctx, r)
	if err != nil {
		return nil, err
	}
	out := &ImportResult{Format: string(doc.Format), DryRun: dryRun, Skipped: []ImportSkip{}, Issues: []string{}, Items: []ImportItem{}}
	for _, is := range doc.Issues {
		if len(out.Issues) >= maxListedIssues {
			break
		}
		out.Issues = append(out.Issues, truncate(is.String(), 300))
	}
	plan := planDocument(doc, aid != nil, out)
	now := s.now()
	seen := map[string]bool{}
	var written []*vexdom.Statement
	for _, p := range plan {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		productID, err := s.repo.ResolveProduct(ctx, tenantID, p.purl.Type, p.purl.Namespace, p.purl.Name)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				out.skip(ImportSkip{VulnID: p.vulnID, PURL: p.raw, Reason: "package not in the inventory"})
				continue
			}
			return out, err
		}
		st := &vexdom.Statement{
			ID: shared.NewID(), TenantID: tenantID, VulnID: p.vulnID, ProductID: productID, AssetID: aid,
			Status: vexdom.Status(p.vex.Status), Justification: string(p.vex.Justification),
			ImpactStatement: p.vex.Statement, Origin: vexdom.OriginDocument,
			DocumentRef: documentRef(doc.Format, p.vex.Source), CreatedBy: actorID(actx), UpdatedBy: actorID(actx),
		}
		if p.purl.Version != "" {
			st.Versions = []string{p.purl.Version}
		}
		if st.Status == vexdom.StatusNotAffected && st.Justification == "" && st.ImpactStatement == "" && p.vex.NativeJustification != "" {
			st.ImpactStatement = "Justification: " + p.vex.NativeJustification
		}
		if err := st.Normalize(now); err != nil {
			out.skip(ImportSkip{VulnID: p.vulnID, PURL: p.raw, Reason: strings.TrimPrefix(err.Error(), shared.ErrValidation.Error()+": ")})
			continue
		}
		key := subjectKey(st)
		if seen[key] {
			out.skip(ImportSkip{VulnID: p.vulnID, PURL: p.raw, Reason: "duplicate of an earlier statement in the document"})
			continue
		}
		seen[key] = true
		out.Statements++
		item := ImportItem{VulnID: st.VulnID, PURL: p.raw, ProductID: productID.String(), Versions: st.Versions,
			Status: string(st.Status), Justification: st.Justification}
		existing, err := s.repo.FindBySubject(ctx, st)
		switch {
		case errors.Is(err, vexdom.ErrNotFound):
			item.Action = "create"
			out.Created++
			if !dryRun {
				if err := s.repo.Create(ctx, st); err != nil {
					return out, err
				}
				written = append(written, st)
			}
		case err != nil:
			return out, err
		case existing.Origin == vexdom.OriginManual:
			out.Statements--
			out.skip(ImportSkip{VulnID: p.vulnID, PURL: p.raw, Reason: "a statement written in the organization covers this already"})
			continue
		case sameContent(existing, st):
			item.Action = "unchanged"
			out.Unchanged++
			// Applied again: idempotent, and finishes an earlier import
			// whose application was interrupted.
			written = append(written, existing)
		default:
			item.Action = "update"
			out.Updated++
			if !dryRun {
				existing.Status, existing.Justification = st.Status, st.Justification
				existing.ImpactStatement, existing.DocumentRef, existing.UpdatedBy = st.ImpactStatement, st.DocumentRef, st.UpdatedBy
				if err := s.repo.Update(ctx, existing); err != nil {
					return out, err
				}
				written = append(written, existing)
			}
		}
		if len(out.Items) < maxListedItems {
			out.Items = append(out.Items, item)
		}
	}
	if dryRun {
		return out, nil
	}
	for _, st := range written {
		r, err := s.applySubject(ctx, st)
		out.Applied.add(r)
		if err != nil {
			s.auditImport(ctx, actx, out, aid)
			return out, fmt.Errorf("apply vex statement: %w", err)
		}
	}
	s.auditImport(ctx, actx, out, aid)
	return out, nil
}

func documentRef(f importer.Format, source string) string {
	ref := string(f) + " document"
	if source = strings.TrimSpace(source); source != "" {
		ref += ": " + source
	}
	return truncate(ref, vexdom.MaxDocumentRef)
}

func subjectKey(st *vexdom.Statement) string {
	a := ""
	if st.AssetID != nil {
		a = st.AssetID.String()
	}
	return st.VulnID + "|" + st.ProductID.String() + "|" + a + "|" + strings.Join(st.Versions, ",") + "|" + st.VersionRange
}

func sameContent(a, b *vexdom.Statement) bool {
	return a.Status == b.Status && a.Justification == b.Justification && a.ImpactStatement == b.ImpactStatement &&
		a.DocumentRef == b.DocumentRef
}

func (s *Service) auditImport(ctx context.Context, actx auditapp.AuditContext, out *ImportResult, assetID *shared.ID) {
	ev := auditapp.NewSuccessEvent(auditdom.ActionVEXStatementImported, auditdom.ResourceTypeVEXStatement, "").
		WithMessage(fmt.Sprintf("VEX document imported (%s): %d created, %d updated", out.Format, out.Created, out.Updated)).
		WithMetadata("format", out.Format).
		WithMetadata("created", out.Created).WithMetadata("updated", out.Updated).
		WithMetadata("skipped", out.SkippedTotal).
		WithMetadata("closed", out.Applied.Closed).WithMetadata("reopened", out.Applied.Reopened).
		WithMetadata("finding_ids", out.Applied.FindingIDs)
	if assetID != nil {
		ev = ev.WithMetadata("asset_id", assetID.String())
	}
	s.logAudit(ctx, actx, ev)
}
