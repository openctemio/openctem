package postgres

// Source retirement (docs/architecture/source-retirement.md): the
// classifier, the archive and its journal, never losing information,
// idempotence, exact restore, tenant isolation and the ingest policy bump.

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/sourceretire"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

type retireFixture struct {
	*receiptFixture
	repo   *SourceRetirementRepository
	sensor shared.ID
}

func newRetireFixture(t *testing.T) *retireFixture {
	t.Helper()
	f := newReceiptFixture(t)
	return &retireFixture{receiptFixture: f, repo: NewSourceRetirementRepository(&DB{DB: f.db}), sensor: f.sensor(f.tenant)}
}

// seed inserts a finding with a status and severity.
func (f *retireFixture) seed(tenant shared.ID, fp, status, severity string) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	closure := any(nil)
	if status == "resolved" {
		closure = "fixed"
	}
	verification := any(nil)
	if status == "resolved" {
		verification = "covered_scan"
	}
	asset := f.asset
	if tenant != f.tenant {
		asset = seedTestAsset(f.ctx, f.t, f.db, tenant)
	}
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
			severity, fingerprint, status, title, description, closure_reason, verification)
		VALUES ($1, $2, $3, 'va', 'junk', 'm', $4, $5::text, $6, 'title '||$5::text, 'evidence text '||$5::text, $7, $8)`,
		id.String(), tenant.String(), asset.String(), severity, fp, status, closure, verification); err != nil {
		f.t.Fatalf("seed finding %s: %v", fp, err)
	}
	return id
}

// sight records a sighting of finding by a source.
func (f *retireFixture) sight(tenant, finding shared.ID, channel string, sensor *shared.ID, sender, tool string) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO finding_sightings (tenant_id, finding_id, channel, sensor_id, sender,
			tool, first_seen_at, last_seen_at) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
		tenant.String(), finding.String(), channel, nullableID(sensor), sender, tool); err != nil {
		f.t.Fatalf("seed sighting: %v", err)
	}
}

func (f *retireFixture) junk(tenant, finding shared.ID) {
	f.sight(tenant, finding, "scan", &f.sensor, "", "junk")
}

func (f *retireFixture) status(id shared.ID) (status, reason, resolution string) {
	f.t.Helper()
	var r, res *string
	if err := f.db.QueryRowContext(f.ctx, `SELECT status, closure_reason, resolution FROM findings WHERE id = $1`,
		id.String()).Scan(&status, &r, &res); err != nil {
		f.t.Fatalf("status: %v", err)
	}
	if r != nil {
		reason = *r
	}
	if res != nil {
		resolution = *res
	}
	return status, reason, resolution
}

func (f *retireFixture) selector() sourceretire.Selector {
	s := f.sensor
	return sourceretire.Selector{Kind: sourceretire.KindSensorTool, SensorID: &s, Tool: "JUNK"}
}

func (f *retireFixture) create(tenant shared.ID, sel sourceretire.Selector, opts sourceretire.Options) *sourceretire.Retirement {
	f.t.Helper()
	opts, err := opts.Normalize()
	if err != nil {
		f.t.Fatal(err)
	}
	ret, err := f.repo.Create(f.ctx, &sourceretire.Retirement{TenantID: tenant, Selector: sel, Options: opts,
		Reason: "junk scanner, wrong results", Label: "junk"})
	if err != nil {
		f.t.Fatalf("create: %v", err)
	}
	return ret
}

func (f *retireFixture) archiveAll(tenant, id shared.ID) []shared.ID {
	f.t.Helper()
	var all []shared.ID
	for range 10 {
		res, err := f.repo.ArchiveBatch(f.ctx, tenant, id, time.Now().UTC())
		if err != nil {
			f.t.Fatalf("archive batch: %v", err)
		}
		all = append(all, res.IDs...)
		if res.Finished {
			return all
		}
	}
	f.t.Fatal("archive did not finish")
	return nil
}

type retireSet struct {
	soleNew, soleCritical, corroborated, inProgress, secret, assigned, closed, viaRetired, kev shared.ID
}

func (f *retireFixture) seedSet() retireSet {
	f.t.Helper()
	var s retireSet
	s.soleNew = f.seed(f.tenant, "sole-new", "new", "high")
	f.junk(f.tenant, s.soleNew)
	s.soleCritical = f.seed(f.tenant, "sole-critical", "confirmed", "critical")
	f.junk(f.tenant, s.soleCritical)
	if _, err := f.db.ExecContext(f.ctx, `UPDATE findings SET sla_deadline = NOW() + interval '7 days' WHERE id = $1`,
		s.soleCritical.String()); err != nil {
		f.t.Fatal(err)
	}
	s.kev = f.seed(f.tenant, "sole-kev", "new", "low")
	f.junk(f.tenant, s.kev)
	if _, err := f.db.ExecContext(f.ctx, `UPDATE findings SET is_in_kev = true WHERE id = $1`, s.kev.String()); err != nil {
		f.t.Fatal(err)
	}
	s.corroborated = f.seed(f.tenant, "corroborated", "new", "high")
	f.junk(f.tenant, s.corroborated)
	f.sight(f.tenant, s.corroborated, "upload", nil, "", "nessus")
	s.inProgress = f.seed(f.tenant, "in-progress", "in_progress", "high")
	f.junk(f.tenant, s.inProgress)
	s.secret = f.seed(f.tenant, "secret", "new", "high")
	f.junk(f.tenant, s.secret)
	if _, err := f.db.ExecContext(f.ctx, `UPDATE findings SET finding_type = 'secret' WHERE id = $1`, s.secret.String()); err != nil {
		f.t.Fatal(err)
	}
	s.assigned = f.seed(f.tenant, "assigned", "new", "medium")
	f.junk(f.tenant, s.assigned)
	user := seedUser(f.ctx, f.t, &DB{DB: f.db})
	if _, err := f.db.ExecContext(f.ctx, `UPDATE findings SET assigned_to = $2 WHERE id = $1`,
		s.assigned.String(), user.String()); err != nil {
		f.t.Fatal(err)
	}
	s.closed = f.seed(f.tenant, "closed", "resolved", "high")
	f.junk(f.tenant, s.closed)
	// Reported by junk and by a connector that is itself retired: a
	// retired source never corroborates.
	s.viaRetired = f.seed(f.tenant, "via-retired", "new", "medium")
	f.junk(f.tenant, s.viaRetired)
	f.sight(f.tenant, s.viaRetired, "connector", nil, "old-feed", "feedtool")
	f.create(f.tenant, sourceretire.Selector{Kind: sourceretire.KindConnector, Sender: "old-feed"},
		sourceretire.Options{Mode: sourceretire.ModeKeepOpen})
	// Not reported by the source at all.
	other := f.seed(f.tenant, "other", "new", "high")
	f.sight(f.tenant, other, "upload", nil, "", "nessus")
	return s
}

func TestSourceRetirement_PreviewClassifies_DB(t *testing.T) {
	f := newRetireFixture(t)
	f.seedSet()
	p, err := f.repo.Preview(f.ctx, f.tenant, f.selector().Normalize(), sourceretire.Options{Mode: sourceretire.ModeArchive}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := sourceretire.Preview{Total: 9, Archive: 4, CriticalOrKEV: 2, WithSLA: 1, Corroborated: 1, KeptEngaged: 1,
		KeptInProgress: 1, KeptSecret: 1, AlreadyClosed: 1}
	if p.Total != want.Total || p.Archive != want.Archive || p.CriticalOrKEV != want.CriticalOrKEV ||
		p.Corroborated != want.Corroborated || p.WithSLA != want.WithSLA || p.KeptEngaged != want.KeptEngaged || p.KeptInProgress != want.KeptInProgress ||
		p.KeptSecret != want.KeptSecret || p.AlreadyClosed != want.AlreadyClosed {
		t.Fatalf("preview = %+v, want %+v", *p, want)
	}
	if p.ArchiveBySeverity["critical"] != 1 || p.ArchiveBySeverity["high"] != 1 || p.ArchiveBySeverity["medium"] != 1 {
		t.Fatalf("by severity = %v", p.ArchiveBySeverity)
	}
	// Advanced: only critical and high, findings with an assignee too.
	p, err = f.repo.Preview(f.ctx, f.tenant, f.selector(), sourceretire.Options{Mode: sourceretire.ModeArchive,
		Severities: []vulnerability.Severity{"critical", "high"}, IncludeEngaged: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Archive != 2 || p.KeptSeveritySkipped != 3 || p.KeptEngaged != 0 {
		t.Fatalf("advanced preview = %+v", *p)
	}
}

// The archive moves exactly what the preview counted, keeps every piece of
// information (text, sightings, source records), is idempotent, and the
// restore returns exactly that set, leaving a finding someone changed since.
func TestSourceRetirement_ArchiveRestoreExact_DB(t *testing.T) {
	f := newRetireFixture(t)
	s := f.seedSet()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO finding_source_records (tenant_id, finding_id, channel, sensor_id,
			sender, tool, title, first_seen_at, last_seen_at) VALUES ($1, $2, 'scan', $3, '', 'junk', 'junk title', NOW(), NOW())`,
		f.tenant.String(), s.soleNew.String(), f.sensor.String()); err != nil {
		t.Fatalf("seed source record: %v", err)
	}
	var slaBefore time.Time
	if err := f.db.QueryRowContext(f.ctx, `SELECT sla_deadline FROM findings WHERE id = $1`, s.soleCritical.String()).Scan(&slaBefore); err != nil {
		t.Fatal(err)
	}
	versionBefore := f.count(`SELECT COALESCE((SELECT version FROM ingest_policy_versions WHERE tenant_id = $1), 0)`, f.tenant.String())

	sel := f.selector().Normalize()
	pre, err := f.repo.Preview(f.ctx, f.tenant, sel, sourceretire.Options{Mode: sourceretire.ModeArchive}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ret := f.create(f.tenant, sel, sourceretire.Options{})
	if ret.State != sourceretire.StateApplying {
		t.Fatalf("state = %s", ret.State)
	}
	if v := f.count(`SELECT version FROM ingest_policy_versions WHERE tenant_id = $1`, f.tenant.String()); v <= versionBefore {
		t.Fatalf("policy version not bumped: %d -> %d", versionBefore, v)
	}
	moved := f.archiveAll(f.tenant, ret.ID)
	if len(moved) != pre.Archive {
		t.Fatalf("archived %d, preview said %d", len(moved), pre.Archive)
	}
	for _, id := range []shared.ID{s.soleNew, s.soleCritical, s.kev, s.viaRetired} {
		st, reason, res := f.status(id)
		if st != "resolved" || reason != "obsolete_source" || res != "source_retired" {
			t.Fatalf("finding %s = %s/%s/%s, want resolved/obsolete_source/source_retired", id, st, reason, res)
		}
	}
	for _, id := range []shared.ID{s.corroborated, s.inProgress, s.secret, s.assigned} {
		if st, _, _ := f.status(id); st == "resolved" {
			t.Fatalf("finding %s was archived but must stay open", id)
		}
	}
	if st, reason, _ := f.status(s.closed); st != "resolved" || reason != "fixed" {
		t.Fatalf("closed finding changed: %s/%s", st, reason)
	}
	// Never lose information: text, sightings and source records stay.
	if n := f.count(`SELECT count(*) FROM findings WHERE id = $1 AND description = 'evidence text sole-new'`, s.soleNew.String()); n != 1 {
		t.Fatal("finding text changed")
	}
	if n := f.count(`SELECT count(*) FROM finding_sightings WHERE finding_id = $1`, s.soleNew.String()); n != 1 {
		t.Fatalf("sightings = %d", n)
	}
	if n := f.count(`SELECT count(*) FROM finding_source_records WHERE finding_id = $1 AND title = 'junk title'`, s.soleNew.String()); n != 1 {
		t.Fatal("source record lost")
	}
	// The timeline records who archived it.
	if n := f.count(`SELECT count(*) FROM finding_activities WHERE finding_id = $1`, s.soleNew.String()); n < 1 {
		t.Fatal("no timeline entry")
	}
	// Idempotent: a second create returns the live retirement, a second
	// batch changes nothing.
	again := f.create(f.tenant, sel, sourceretire.Options{})
	if !again.AlreadyRetired || again.ID != ret.ID {
		t.Fatalf("second create = %+v", again)
	}
	res, err := f.repo.ArchiveBatch(f.ctx, f.tenant, ret.ID, time.Now().UTC())
	if err != nil || res.Moved != 0 || !res.Finished {
		t.Fatalf("second batch = %+v, %v", res, err)
	}
	got, err := f.repo.Get(f.ctx, f.tenant, ret.ID)
	if err != nil || got.State != sourceretire.StateActive || got.ArchivedCount != 4 {
		t.Fatalf("after archive: %+v, %v", got, err)
	}
	live, err := f.repo.Live(f.ctx, f.tenant)
	if err != nil || len(live) != 2 {
		t.Fatalf("live = %v, %v", live, err)
	}

	// A person reopens one archived finding before the restore.
	if _, err := f.db.ExecContext(f.ctx, `UPDATE findings SET status = 'confirmed', closure_reason = NULL, verification = NULL,
		resolution = NULL, resolved_at = NULL WHERE id = $1`, s.viaRetired.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.StartRestore(f.ctx, f.tenant, ret.ID, nil, "the source is fixed"); err != nil {
		t.Fatal(err)
	}
	if live, _ = f.repo.Live(f.ctx, f.tenant); len(live) != 1 {
		t.Fatalf("the restored source is still live: %v", live)
	}
	for range 5 {
		r, err := f.repo.RestoreBatch(f.ctx, f.tenant, ret.ID, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if r.Finished {
			break
		}
	}
	for id, want := range map[shared.ID]string{s.soleNew: "new", s.soleCritical: "confirmed", s.kev: "new", s.viaRetired: "confirmed"} {
		st, reason, res := f.status(id)
		if st != want || reason != "" || (res != "" && id != s.viaRetired) {
			t.Fatalf("restored %s = %s/%s/%s, want %s", id, st, reason, res, want)
		}
	}
	var slaAfter time.Time
	if err := f.db.QueryRowContext(f.ctx, `SELECT sla_deadline FROM findings WHERE id = $1`, s.soleCritical.String()).Scan(&slaAfter); err != nil {
		t.Fatal(err)
	}
	if !slaAfter.Equal(slaBefore) {
		t.Fatalf("SLA deadline %v, was %v", slaAfter, slaBefore)
	}
	got, _ = f.repo.Get(f.ctx, f.tenant, ret.ID)
	if got.State != sourceretire.StateRestored || got.RestoredCount != 3 || got.ChangedCount != 1 || got.RestoredAt == nil {
		t.Fatalf("after restore: %+v", got)
	}
	// The source can be retired again.
	if again := f.create(f.tenant, sel, sourceretire.Options{Mode: sourceretire.ModeKeepOpen}); again.AlreadyRetired {
		t.Fatal("a restored source must be retirable again")
	}
}

// Another tenant's findings never match, even with a forged sighting of the
// same sensor id, and another tenant can neither read nor drive a
// retirement.
func TestSourceRetirement_TenantIsolation_DB(t *testing.T) {
	f := newRetireFixture(t)
	mine := f.seed(f.tenant, "mine", "new", "high")
	f.junk(f.tenant, mine)
	other := seedTestTenant(f.ctx, t, f.db)
	theirs := f.seed(other, "theirs", "new", "high")
	f.junk(other, theirs)

	ret := f.create(f.tenant, f.selector(), sourceretire.Options{})
	if _, err := f.repo.ArchiveBatch(f.ctx, other, ret.ID, time.Now().UTC()); !errors.Is(err, sourceretire.ErrNotFound) {
		t.Fatalf("other tenant archive batch: %v", err)
	}
	if _, err := f.repo.Get(f.ctx, other, ret.ID); !errors.Is(err, sourceretire.ErrNotFound) {
		t.Fatalf("other tenant get: %v", err)
	}
	if _, err := f.repo.StartRestore(f.ctx, other, ret.ID, nil, "x"); !errors.Is(err, sourceretire.ErrNotFound) {
		t.Fatalf("other tenant restore: %v", err)
	}
	if list, _ := f.repo.List(f.ctx, other, true, 10); len(list) != 0 {
		t.Fatalf("other tenant lists %d", len(list))
	}
	f.archiveAll(f.tenant, ret.ID)
	if st, _, _ := f.status(mine); st != "resolved" {
		t.Fatalf("mine = %s", st)
	}
	if st, _, _ := f.status(theirs); st != "new" {
		t.Fatalf("another tenant's finding changed: %s", st)
	}
	p, err := f.repo.Preview(f.ctx, other, f.selector(), sourceretire.Options{Mode: sourceretire.ModeArchive}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Archive != 1 {
		// theirs is still open in their own tenant; the counts are their own only
		t.Fatalf("other tenant preview counts %d", p.Archive)
	}
	if n := f.count(`SELECT count(*) FROM source_retirement_findings WHERE tenant_id = $1`, other.String()); n != 0 {
		t.Fatalf("journal rows in the other tenant: %d", n)
	}
}

// Keep open blocks only: nothing is archived.
func TestSourceRetirement_KeepOpen_DB(t *testing.T) {
	f := newRetireFixture(t)
	id := f.seed(f.tenant, "keep", "new", "high")
	f.junk(f.tenant, id)
	ret := f.create(f.tenant, f.selector(), sourceretire.Options{Mode: sourceretire.ModeKeepOpen})
	if ret.State != sourceretire.StateActive {
		t.Fatalf("state = %s", ret.State)
	}
	if res, err := f.repo.ArchiveBatch(f.ctx, f.tenant, ret.ID, time.Now().UTC()); err != nil || res.Moved != 0 {
		t.Fatalf("keep open archived: %+v %v", res, err)
	}
	if st, _, _ := f.status(id); st != "new" {
		t.Fatalf("status = %s", st)
	}
}
