package cirun

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	appimportmapping "github.com/openctemio/openctem/api/internal/app/importmapping"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/ingestqueue"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	dom "github.com/openctemio/openctem/api/pkg/domain/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A CI upload through an import mapping pins the version resolved at accept
// and the worker applies exactly it, in the job's organization.

const ciMapDoc = `{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "identity": ["title"],
  "records": [{"kind": "finding", "set": {"title": "/title", "severity": {"const": "SEV"}}}]}`

type memMappings struct {
	appimportmapping.Repository
	mappings map[shared.ID]*dom.Mapping
	versions map[shared.ID][]*dom.Version
}

func newMemMappings() *memMappings {
	return &memMappings{mappings: map[shared.ID]*dom.Mapping{}, versions: map[shared.ID][]*dom.Version{}}
}

func (r *memMappings) Count(context.Context, shared.ID) (int, error) { return len(r.mappings), nil }
func (r *memMappings) Create(_ context.Context, m *dom.Mapping, v *dom.Version) error {
	r.mappings[m.ID], r.versions[m.ID] = m, []*dom.Version{v}
	return nil
}
func (r *memMappings) Get(_ context.Context, t, id shared.ID) (*dom.Mapping, error) {
	if m := r.mappings[id]; m != nil && m.TenantID == t {
		c := *m
		return &c, nil
	}
	return nil, shared.ErrNotFound
}
func (r *memMappings) GetByName(_ context.Context, t shared.ID, name string) (*dom.Mapping, error) {
	for _, m := range r.mappings {
		if m.TenantID == t && m.Name == name {
			c := *m
			return &c, nil
		}
	}
	return nil, shared.ErrNotFound
}
func (r *memMappings) GetVersion(_ context.Context, t, id shared.ID, n int) (*dom.Version, error) {
	m := r.mappings[id]
	if m == nil || m.TenantID != t {
		return nil, shared.ErrNotFound
	}
	if n == 0 {
		n = m.LatestVersion
	}
	for _, v := range r.versions[id] {
		if v.Version == n {
			return v, nil
		}
	}
	return nil, shared.ErrNotFound
}
func (r *memMappings) AddVersion(_ context.Context, v *dom.Version, _ int) error {
	r.versions[v.MappingID] = append(r.versions[v.MappingID], v)
	r.mappings[v.MappingID].LatestVersion = v.Version
	return nil
}

type memQueue struct {
	UploadQueue
	parts map[shared.ID][]byte
	job   *ingestjob.Job
}

func (q *memQueue) StagePart(_ context.Context, _, id shared.ID, _ int, _ string, body []byte) error {
	q.parts[id] = body
	return nil
}
func (q *memQueue) Commit(_ context.Context, j *ingestjob.Job, admit func() error) (*ingestjob.Job, bool, error) {
	if err := admit(); err != nil {
		return nil, false, err
	}
	q.job = j
	return j, true, nil
}
func (q *memQueue) Parts(_ context.Context, j *ingestjob.Job) ([]ingestqueue.OpenedPart, error) {
	return []ingestqueue.OpenedPart{{Part: 0, Name: "results", Body: q.parts[j.ID()]}}, nil
}

type memRuns struct {
	cirun.Repository
	run *cirun.Run
}

func (r *memRuns) GetRun(_ context.Context, t, id shared.ID) (*cirun.Run, error) {
	if r.run.TenantID != t || r.run.ID != id {
		return nil, shared.ErrNotFound
	}
	return r.run, nil
}
func (r *memRuns) ReserveRunReport(context.Context, shared.ID, shared.ID) error { return nil }
func (r *memRuns) RecordRunReport(context.Context, shared.ID, shared.ID, []string) error {
	return nil
}
func (r *memRuns) RecordRunTools(context.Context, shared.ID, shared.ID, []cirun.ToolLabel) error {
	return nil
}
func (r *memRuns) ClearCarriedCapabilities(context.Context, shared.ID, shared.ID, string) error {
	return nil
}

type recIngester struct{ reports []*ctis.Report }

func (i *recIngester) IngestForCIRun(_ context.Context, _, runID shared.ID, _ string, rep *ctis.Report) (*ingest.Output, error) {
	i.reports = append(i.reports, rep)
	return &ingest.Output{ReportID: runID.String()}, nil
}

type ciMapFixture struct {
	svc    *Service
	maps   *appimportmapping.Service
	store  *memMappings
	queue  *memQueue
	ing    *recIngester
	run    *cirun.Run
	tenant shared.ID
}

func newCIMapFixture(t *testing.T) *ciMapFixture {
	t.Helper()
	tenant := shared.NewID()
	run := &cirun.Run{ID: shared.NewID(), TenantID: tenant, Repository: "acme/web", RepositoryAssetID: shared.NewID()}
	ing := &recIngester{}
	svc := NewService(Deps{Repo: &memRuns{run: run}, Ingester: ing}, Config{}, nil)
	q := &memQueue{parts: map[shared.ID][]byte{}}
	svc.SetUploadQueue(q, nil)
	store := newMemMappings()
	maps := appimportmapping.NewService(store)
	svc.SetMappingResolver(maps)
	return &ciMapFixture{svc: svc, maps: maps, store: store, queue: q, ing: ing, run: run, tenant: tenant}
}

func (f *ciMapFixture) create(t *testing.T, tenant shared.ID, name, sev string) *dom.Mapping {
	t.Helper()
	m, _, err := f.maps.Create(context.Background(), appimportmapping.CreateInput{TenantID: tenant, Name: name,
		Document: json.RawMessage(strings.Replace(ciMapDoc, "SEV", sev, 1))})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// pinOf resolves a mapping name the way the handler does at accept.
func (f *ciMapFixture) pinOf(t *testing.T, tenant shared.ID, name string) *MappingPin {
	t.Helper()
	r, err := f.maps.Resolve(context.Background(), tenant, dom.FormatRef{Ref: name})
	if err != nil {
		t.Fatal(err)
	}
	return &MappingPin{ID: r.Mapping.ID.String(), Format: r.Format()}
}

var ciCSV = []byte("title\nOpenSSL out of date\n")

func TestCIUpload_MappingAppliesThePinnedVersion(t *testing.T) {
	f := newCIMapFixture(t)
	m := f.create(t, f.tenant, "legacy-vm", "low")
	if _, err := f.svc.AcceptUpload(context.Background(), f.run, ciCSV, false, f.pinOf(t, f.tenant, "legacy-vm")); err != nil {
		t.Fatal(err)
	}
	// Version 2 (critical) is published before the worker runs.
	if _, _, err := f.maps.AddVersion(context.Background(), appimportmapping.AddVersionInput{TenantID: f.tenant, ID: m.ID,
		Document: json.RawMessage(strings.Replace(ciMapDoc, "SEV", "critical", 1))}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ProcessUploadJob(context.Background(), f.queue.job); err != nil {
		t.Fatal(err)
	}
	if len(f.ing.reports) != 1 || len(f.ing.reports[0].Findings) != 1 {
		t.Fatalf("reports %+v", f.ing.reports)
	}
	rep := f.ing.reports[0]
	if rep.Findings[0].Severity != ctis.SeverityLow || rep.Tool == nil || rep.Tool.Version != "v1" {
		t.Fatalf("applied %q by %+v, want the pinned version 1 (low)", rep.Findings[0].Severity, rep.Tool)
	}
	if len(rep.Assets) != 1 || rep.Assets[0].Value != "acme/web" {
		t.Fatalf("assets %+v, want the run's repository", rep.Assets)
	}
}

func TestCIUpload_MappingGoneFailsWithAFixedCode(t *testing.T) {
	f := newCIMapFixture(t)
	f.create(t, f.tenant, "legacy-vm", "low")
	pin := f.pinOf(t, f.tenant, "legacy-vm")
	if _, err := f.svc.AcceptUpload(context.Background(), f.run, ciCSV, false, pin); err != nil {
		t.Fatal(err)
	}
	// Deleted (a Resolve in the job's organization finds nothing).
	delete(f.store.mappings, shared.MustIDFromString(pin.ID))
	_, err := f.svc.ProcessUploadJob(context.Background(), f.queue.job)
	var perm *ingestjob.PermanentError
	if !errors.As(err, &perm) || perm.Code != UploadErrorMappingGone {
		t.Fatalf("err = %v, want permanent %s", err, UploadErrorMappingGone)
	}
	if len(f.ing.reports) != 0 {
		t.Fatalf("applied %d reports from a deleted mapping", len(f.ing.reports))
	}
}

// The worker resolves in the job's organization: a pin naming another
// organization's mapping is refused, never applied to the run.
func TestCIUpload_MappingOfAnotherOrganizationIsRefused(t *testing.T) {
	f := newCIMapFixture(t)
	other := shared.NewID()
	f.create(t, other, "foreign-vm", "critical")
	pin := f.pinOf(t, other, "foreign-vm")
	if _, err := f.svc.AcceptUpload(context.Background(), f.run, ciCSV, false, pin); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.ProcessUploadJob(context.Background(), f.queue.job)
	var perm *ingestjob.PermanentError
	if !errors.As(err, &perm) || perm.Code != UploadErrorMappingGone {
		t.Fatalf("err = %v, want permanent %s", err, UploadErrorMappingGone)
	}
	if len(f.ing.reports) != 0 {
		t.Fatalf("applied %d reports from another organization's mapping", len(f.ing.reports))
	}
}

func (q *memQueue) Admit(context.Context, shared.ID) error { return nil }
