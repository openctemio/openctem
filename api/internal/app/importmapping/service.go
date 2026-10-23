// Package importmapping serves an organization's import mappings: CRUD with
// immutable versions, validation, a preview on a sample that stores nothing,
// and the resolution of "format=mapping:<ref>[@<version>]" for imports.
//
// Design: docs/rfcs/RFC-126-import-mappings.md.
package importmapping

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer/mapping"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	dom "github.com/openctemio/openctem/api/pkg/domain/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Bounds of a preview.
const (
	// MaxSampleBytes is the largest sample a preview reads.
	MaxSampleBytes = 5 << 20
	// PreviewItems is how many records a preview returns.
	PreviewItems = 50
	// previewRecords bounds the records a preview maps (identity
	// collisions are counted over all of them).
	previewRecords = 10_000
)

// previewTimeout bounds one preview (a variable for tests).
var previewTimeout = 10 * time.Second

// Repository stores mappings and their versions. Every method is scoped to
// the organization it is given.
type Repository interface {
	// Create stores a mapping and its first version in one transaction.
	// A name already used in the organization is shared.ErrConflict.
	Create(ctx context.Context, m *dom.Mapping, v *dom.Version) error
	List(ctx context.Context, tenantID shared.ID) ([]*dom.Mapping, error)
	Count(ctx context.Context, tenantID shared.ID) (int, error)
	Get(ctx context.Context, tenantID, id shared.ID) (*dom.Mapping, error)
	GetByName(ctx context.Context, tenantID shared.ID, name string) (*dom.Mapping, error)
	// GetVersion returns one version with its document; version 0 is the
	// latest.
	GetVersion(ctx context.Context, tenantID, id shared.ID, version int) (*dom.Version, error)
	// ListVersions returns the versions, newest first, without documents.
	ListVersions(ctx context.Context, tenantID, id shared.ID) ([]*dom.Version, error)
	// AddVersion stores v as version expectedLatest+1 when the mapping's
	// latest version is still expectedLatest (else shared.ErrConflict).
	AddVersion(ctx context.Context, v *dom.Version, expectedLatest int) error
	Update(ctx context.Context, tenantID, id shared.ID, name, description string) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
}

// Service is the import mapping service.
type Service struct {
	repo Repository
	now  func() time.Time
}

// NewService builds the service.
func NewService(repo Repository) *Service {
	return &Service{repo: repo, now: time.Now}
}

// ValidationError lists the problems of a mapping document.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "the mapping has errors: " + strings.Join(e.Problems, "; ")
}

func (e *ValidationError) Unwrap() error { return shared.ErrValidation }

// IdentityChangeError is ErrIdentityChangeUnconfirmed with the identities.
type IdentityChangeError struct {
	Previous []string
	Next     []string
}

func (e *IdentityChangeError) Error() string { return dom.ErrIdentityChangeUnconfirmed.Error() }

func (e *IdentityChangeError) Unwrap() error { return dom.ErrIdentityChangeUnconfirmed }

// compile runs the language and organization checks on a document.
func compile(doc json.RawMessage) (*mapping.Mapping, error) {
	if len(doc) == 0 {
		return nil, &ValidationError{Problems: []string{"mapping is required"}}
	}
	if len(doc) > dom.MaxDocumentBytes {
		return nil, &ValidationError{Problems: []string{fmt.Sprintf("mapping is larger than %d bytes", dom.MaxDocumentBytes)}}
	}
	m, problems := dom.Compile(doc)
	if len(problems) > 0 {
		return nil, &ValidationError{Problems: problems}
	}
	return m, nil
}

// Validation is the result of Validate.
type Validation struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors"`
	Source   string   `json:"source,omitempty"`
	Identity []string `json:"identity"`
}

// Validate checks a document without storing it.
func (s *Service) Validate(doc json.RawMessage) Validation {
	m, err := compile(doc)
	if err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			return Validation{Errors: ve.Problems, Identity: []string{}}
		}
		return Validation{Errors: []string{err.Error()}, Identity: []string{}}
	}
	return Validation{Valid: true, Errors: []string{}, Source: m.Source(), Identity: nonNil(m.Identity())}
}

// CreateInput creates a mapping.
type CreateInput struct {
	TenantID    shared.ID
	ActorID     *shared.ID
	Name        string
	Description string
	Document    json.RawMessage
	Note        string
}

// Create stores a new mapping as version 1.
func (s *Service) Create(ctx context.Context, in CreateInput) (*dom.Mapping, *dom.Version, error) {
	if err := dom.ValidateName(in.Name); err != nil {
		return nil, nil, err
	}
	if err := dom.ValidateText(in.Description, in.Note); err != nil {
		return nil, nil, err
	}
	m, err := compile(in.Document)
	if err != nil {
		return nil, nil, err
	}
	n, err := s.repo.Count(ctx, in.TenantID)
	if err != nil {
		return nil, nil, err
	}
	if n >= dom.MaxPerTenant {
		return nil, nil, fmt.Errorf("%w: an organization has at most %d import mappings", dom.ErrLimit, dom.MaxPerTenant)
	}
	now := s.now().UTC()
	mp := &dom.Mapping{
		ID: shared.NewID(), TenantID: in.TenantID, Name: in.Name, Description: in.Description,
		Source: m.Source(), LatestVersion: 1, CreatedBy: in.ActorID, CreatedAt: now, UpdatedAt: now,
	}
	v := &dom.Version{
		MappingID: mp.ID, TenantID: in.TenantID, Version: 1, Document: canonical(in.Document),
		Digest: m.Digest(), Identity: nonNil(m.Identity()), Note: in.Note, CreatedBy: in.ActorID, CreatedAt: now,
	}
	if err := s.repo.Create(ctx, mp, v); err != nil {
		return nil, nil, err
	}
	return mp, v, nil
}

// AddVersionInput saves a new version.
type AddVersionInput struct {
	TenantID shared.ID
	ID       shared.ID
	ActorID  *shared.ID
	Document json.RawMessage
	Note     string
	// ConfirmIdentityChange accepts a version whose identity differs from
	// the latest one's.
	ConfirmIdentityChange bool
}

// AddVersion saves a new version. A version whose identity differs from
// the latest is refused with an IdentityChangeError unless confirmed, and
// is then marked identity_changed: findings imported with earlier versions
// keep their identities and are keyed apart from the new ones.
func (s *Service) AddVersion(ctx context.Context, in AddVersionInput) (*dom.Mapping, *dom.Version, error) {
	if err := dom.ValidateText("", in.Note); err != nil {
		return nil, nil, err
	}
	mp, err := s.repo.Get(ctx, in.TenantID, in.ID)
	if err != nil {
		return nil, nil, err
	}
	if mp.LatestVersion >= dom.MaxVersions {
		return nil, nil, fmt.Errorf("%w: a mapping has at most %d versions", dom.ErrLimit, dom.MaxVersions)
	}
	next, err := compile(in.Document)
	if err != nil {
		return nil, nil, err
	}
	if next.Source() != mp.Source {
		return nil, nil, &ValidationError{Problems: []string{fmt.Sprintf("source is %q for this mapping; create a new mapping for another input format", mp.Source)}}
	}
	latest, err := s.repo.GetVersion(ctx, in.TenantID, in.ID, mp.LatestVersion)
	if err != nil {
		return nil, nil, err
	}
	prev, err := mapping.Load(latest.Document)
	if err != nil {
		// A stored version always loaded once; a newer language that
		// refuses it treats the new version as an identity change.
		prev = nil
	}
	changed := prev == nil || dom.IdentityChanged(prev, next)
	if changed && !in.ConfirmIdentityChange {
		return nil, nil, &IdentityChangeError{Previous: nonNil(latest.Identity), Next: nonNil(next.Identity())}
	}
	if next.Digest() == latest.Digest {
		return nil, nil, fmt.Errorf("%w: the mapping is the same as version %d", shared.ErrValidation, latest.Version)
	}
	v := &dom.Version{
		MappingID: mp.ID, TenantID: in.TenantID, Version: mp.LatestVersion + 1, Document: canonical(in.Document),
		Digest: next.Digest(), Identity: nonNil(next.Identity()), IdentityChanged: changed, Note: in.Note,
		CreatedBy: in.ActorID, CreatedAt: s.now().UTC(),
	}
	if err := s.repo.AddVersion(ctx, v, mp.LatestVersion); err != nil {
		return nil, nil, err
	}
	mp.LatestVersion = v.Version
	mp.UpdatedAt = v.CreatedAt
	return mp, v, nil
}

// Update renames a mapping or changes its description. Imports recorded
// under the old name keep it.
func (s *Service) Update(ctx context.Context, tenantID, id shared.ID, name, description *string) (*dom.Mapping, error) {
	mp, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if name != nil {
		if err := dom.ValidateName(*name); err != nil {
			return nil, err
		}
		mp.Name = *name
	}
	if description != nil {
		if err := dom.ValidateText(*description, ""); err != nil {
			return nil, err
		}
		mp.Description = *description
	}
	if err := s.repo.Update(ctx, tenantID, id, mp.Name, mp.Description); err != nil {
		return nil, err
	}
	return mp, nil
}

// Delete removes a mapping and its versions. Findings it imported stay.
func (s *Service) Delete(ctx context.Context, tenantID, id shared.ID) (*dom.Mapping, error) {
	mp, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return mp, s.repo.Delete(ctx, tenantID, id)
}

// List returns the organization's mappings.
func (s *Service) List(ctx context.Context, tenantID shared.ID) ([]*dom.Mapping, error) {
	return s.repo.List(ctx, tenantID)
}

// Detail is a mapping with its latest version and version history.
type Detail struct {
	Mapping  *dom.Mapping   `json:"mapping"`
	Version  *dom.Version   `json:"version"`
	Versions []*dom.Version `json:"versions,omitempty"`
}

// Get returns a mapping with one version (0: the latest) and, for the
// latest, the history.
func (s *Service) Get(ctx context.Context, tenantID, id shared.ID, version int) (*Detail, error) {
	mp, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	v, err := s.repo.GetVersion(ctx, tenantID, id, version)
	if err != nil {
		return nil, err
	}
	d := &Detail{Mapping: mp, Version: v}
	if version == 0 {
		if d.Versions, err = s.repo.ListVersions(ctx, tenantID, id); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// Resolved is the mapping version an import runs.
type Resolved struct {
	Mapping  *dom.Mapping
	Version  *dom.Version
	Compiled *mapping.Mapping
}

// Format is the receipt format of an import through r: "mapping:<name>@<n>".
func (r *Resolved) Format() string {
	return fmt.Sprintf("%s%s@%d", dom.FormatPrefix, r.Mapping.Name, r.Version.Version)
}

// SourceName is the source a mapped import is recorded under.
func (r *Resolved) SourceName() string { return dom.SourcePrefix + r.Mapping.Name }

// Resolve finds the mapping an import format names, in the caller's
// organization only: a reference to another organization's mapping, by
// name or id, is ErrUnknownMapping, the same as a missing one.
func (s *Service) Resolve(ctx context.Context, tenantID shared.ID, ref dom.FormatRef) (*Resolved, error) {
	var mp *dom.Mapping
	var err error
	if id, idErr := shared.IDFromString(ref.Ref); idErr == nil {
		mp, err = s.repo.Get(ctx, tenantID, id)
	} else {
		mp, err = s.repo.GetByName(ctx, tenantID, ref.Ref)
	}
	if errors.Is(err, shared.ErrNotFound) {
		return nil, dom.ErrUnknownMapping
	}
	if err != nil {
		return nil, err
	}
	v, err := s.repo.GetVersion(ctx, tenantID, mp.ID, ref.Version)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, dom.ErrUnknownMapping
	}
	if err != nil {
		return nil, err
	}
	// Re-check under today's policy: a stored version that no longer
	// passes it is not run.
	m, err := compile(v.Document)
	if err != nil {
		return nil, err
	}
	return &Resolved{Mapping: mp, Version: v, Compiled: m}, nil
}

// ApplyOptions are the bounds of an import through a mapping (the upload
// limits of findingimport).
func ApplyOptions(r *Resolved, maxInput int64) mapping.Options {
	return mapping.Options{
		Tool:          &ctis.Tool{Name: r.SourceName(), Version: fmt.Sprintf("v%d", r.Version.Version)},
		MaxInputBytes: maxInput,
		MaxRecords:    100_000,
		MaxOutputs:    100_000,
		MaxIssues:     100,
	}
}

// Template is a starter mapping.
type Template struct {
	Key         string          `json:"key"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Source      string          `json:"source"`
	Mapping     json.RawMessage `json:"mapping"`
}

//go:embed templates/*.json
var templateFS embed.FS

var templateNames = map[string]string{
	"generic-csv":  "Generic findings CSV",
	"generic-json": "Generic findings JSON",
	"junit-xml":    "JUnit-style XML results",
}

// Templates returns the built-in starter mappings, sorted by key.
func Templates() ([]Template, error) {
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return nil, err
	}
	out := make([]Template, 0, len(entries))
	for _, e := range entries {
		raw, err := templateFS.ReadFile("templates/" + e.Name())
		if err != nil {
			return nil, err
		}
		m, problems := dom.Compile(raw)
		if len(problems) > 0 {
			return nil, fmt.Errorf("template %s: %s", e.Name(), strings.Join(problems, "; "))
		}
		var notes struct {
			Notes string `json:"notes"`
		}
		_ = json.Unmarshal(raw, &notes)
		key := strings.TrimSuffix(e.Name(), ".json")
		out = append(out, Template{Key: key, Name: templateNames[key], Description: notes.Notes, Source: m.Source(), Mapping: raw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// PreviewItem is one record of a preview.
type PreviewItem struct {
	Index int    `json:"index"`
	Kind  string `json:"kind"`
	// Record is the CTIS finding or asset.
	Record any `json:"record"`
	// IdentityKey is the key ingest would store the finding under (on a
	// stand-in asset of the finding's asset type and value).
	IdentityKey string `json:"identity_key,omitempty"`
	// Identity is the value of each declared identity member.
	Identity map[string]string `json:"identity,omitempty"`
}

// PreviewWarning is a problem of the mapping on the sample.
type PreviewWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// PreviewStats count what the preview mapped.
type PreviewStats struct {
	Records   int  `json:"records"`
	Findings  int  `json:"findings"`
	Assets    int  `json:"assets"`
	Skipped   int  `json:"skipped"`
	Truncated bool `json:"truncated"`
}

// Preview is what a mapping makes of a sample. Nothing is stored.
type Preview struct {
	Items    []PreviewItem    `json:"items"`
	Stats    PreviewStats     `json:"stats"`
	Warnings []PreviewWarning `json:"warnings"`
	Issues   []mapping.Issue  `json:"issues"`
	Fields   []string         `json:"fields"`
	Unmapped []string         `json:"unmapped"`
}

// Warning codes.
const (
	WarnIdentityCollision = "identity_collision"
	WarnNoRecords         = "no_records"
	WarnUnmapped          = "unmapped_fields"
	WarnTruncated         = "truncated"
)

// PreviewDocument runs an unsaved document on a sample.
func (s *Service) PreviewDocument(ctx context.Context, doc json.RawMessage, sample io.Reader) (*Preview, error) {
	m, err := compile(doc)
	if err != nil {
		return nil, err
	}
	return runPreview(ctx, m, "preview", sample)
}

// PreviewVersion runs a saved version of the caller's organization.
func (s *Service) PreviewVersion(ctx context.Context, tenantID, id shared.ID, version int, sample io.Reader) (*Preview, error) {
	r, err := s.Resolve(ctx, tenantID, dom.FormatRef{Ref: id.String(), Version: version})
	if err != nil {
		return nil, err
	}
	return runPreview(ctx, r.Compiled, r.Mapping.Name, sample)
}

// ErrSampleTooLarge: the sample is over MaxSampleBytes.
var ErrSampleTooLarge = fmt.Errorf("%w: the sample is larger than %d bytes", shared.ErrValidation, MaxSampleBytes)

func runPreview(ctx context.Context, m *mapping.Mapping, name string, sample io.Reader) (*Preview, error) {
	ctx, cancel := context.WithTimeout(ctx, previewTimeout)
	defer cancel()
	// The whole sample is read first, so one over the cap is refused even
	// when the record cap would stop the mapping before its end.
	data, err := io.ReadAll(io.LimitReader(sample, MaxSampleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: the sample could not be read", shared.ErrValidation)
	}
	if len(data) > MaxSampleBytes {
		return nil, ErrSampleTooLarge
	}
	tool := &ctis.Tool{Name: dom.SourcePrefix + name}
	report, st, err := m.Apply(ctx, bytes.NewReader(data), mapping.Options{
		Tool: tool, Observe: true, MaxInputBytes: MaxSampleBytes,
		MaxRecords: previewRecords, MaxOutputs: previewRecords, MaxIssues: 50,
	})
	switch {
	case errors.Is(err, mapping.ErrInputTooLarge):
		return nil, ErrSampleTooLarge
	case errors.Is(err, context.DeadlineExceeded):
		return nil, fmt.Errorf("%w: the preview took too long", shared.ErrValidation)
	case err != nil:
		// The error names a place in the sample, never its content
		// beyond the parser's short message.
		return nil, &ValidationError{Problems: []string{truncate(err.Error(), 300)}}
	}
	p := &Preview{
		Items:    []PreviewItem{},
		Warnings: []PreviewWarning{},
		Issues:   nonNilIssues(st.Issues),
		Fields:   nonNil(st.Fields),
		Unmapped: nonNil(st.Unmapped),
		Stats: PreviewStats{Records: st.Records, Findings: st.Findings, Assets: st.Assets,
			Skipped: st.Skipped, Truncated: st.Truncated},
	}
	ident := m.Identity()
	keys := map[string]int{}
	collided := 0
	for i := range report.Findings {
		f := &report.Findings[i]
		key := ingest.PreviewFingerprint(ingest.PreviewAssetID(string(f.AssetType), f.AssetValue), f, tool)
		if keys[key]++; keys[key] == 2 {
			collided += 2
		} else if keys[key] > 2 {
			collided++
		}
		if len(p.Items) < PreviewItems {
			p.Items = append(p.Items, PreviewItem{Index: len(p.Items), Kind: mapping.KindFinding, Record: f,
				IdentityKey: key, Identity: identityValues(f, ident)})
		}
	}
	for i := range report.Assets {
		if len(p.Items) >= PreviewItems {
			break
		}
		p.Items = append(p.Items, PreviewItem{Index: len(p.Items), Kind: mapping.KindAsset, Record: &report.Assets[i]})
	}
	if collided > 0 {
		p.Warnings = append(p.Warnings, PreviewWarning{Code: WarnIdentityCollision, Message: fmt.Sprintf(
			"%d of %d findings share an identity with another finding of the sample and would be imported as one; add identity members that tell them apart", collided, len(report.Findings))})
	}
	if st.Records == 0 {
		p.Warnings = append(p.Warnings, PreviewWarning{Code: WarnNoRecords, Message: "the sample has no record the mapping reads"})
	}
	if len(st.Unmapped) > 0 {
		p.Warnings = append(p.Warnings, PreviewWarning{Code: WarnUnmapped, Message: fmt.Sprintf("%d fields of the sample are not mapped", len(st.Unmapped))})
	}
	if st.Truncated {
		p.Warnings = append(p.Warnings, PreviewWarning{Code: WarnTruncated, Message: fmt.Sprintf("the preview stopped after %d records", previewRecords)})
	}
	return p, nil
}

// identityValues reads the declared identity members of a finding through
// its JSON form.
func identityValues(f *ctis.Finding, ident []string) map[string]string {
	if len(ident) == 0 {
		return nil
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	var tree map[string]any
	if json.Unmarshal(raw, &tree) != nil {
		return nil
	}
	out := make(map[string]string, len(ident))
	for _, member := range ident {
		var cur any = tree
		for _, seg := range strings.Split(member, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				cur = nil
				break
			}
			cur = m[seg]
		}
		if cur != nil {
			out[member] = truncate(fmt.Sprint(cur), 256)
		} else {
			out[member] = ""
		}
	}
	return out
}

// canonical compacts a document for storage (the digest is over the
// canonical form the language computes, not over these bytes).
func canonical(doc json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	if err := json.Compact(&buf, doc); err != nil {
		return doc
	}
	return buf.Bytes()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilIssues(s []mapping.Issue) []mapping.Issue {
	if s == nil {
		return []mapping.Issue{}
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
