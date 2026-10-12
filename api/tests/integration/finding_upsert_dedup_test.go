package integration

// RFC-043 P0 (B2): the finding upsert. A row that meets an existing finding
// must not count as created, must not run the new-finding side effects under
// an id that does not exist, and must not erase what the existing finding
// carries (ticket links, metadata). Checked on a migrated database through
// the real ingest service.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type upsertRig struct {
	*v2Rig
	tn    v2Tenant
	svc   *ingest.Service
	agt   *sensor.Sensor
	frepo *postgres.FindingRepository

	mu      sync.Mutex
	created []shared.ID
}

func newUpsertRig(t *testing.T) *upsertRig {
	t.Helper()
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nessus")
	db := &postgres.DB{DB: r.db}
	frepo := postgres.NewFindingRepository(db)
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), frepo,
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	u := &upsertRig{v2Rig: r, tn: tn, svc: svc, frepo: frepo,
		agt: &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}}
	svc.SetFindingCreatedCallback(func(_ context.Context, _ shared.ID, fs []*vulnerability.Finding) {
		u.mu.Lock()
		defer u.mu.Unlock()
		for _, f := range fs {
			u.created = append(u.created, f.ID())
		}
	})
	return u
}

func (u *upsertRig) report(fs ...ctis.Finding) *ctis.Report {
	for i := range fs {
		fs[i].AssetRef = "h"
	}
	return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nessus"},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "h", Type: ctis.AssetTypeHost, Value: "upsert-" + u.tn.tenant.String()[:8] + ".example.com"}},
		Findings: fs}
}

func sshFinding() ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "OpenSSH regreSSHion", Severity: ctis.SeverityHigh,
		RuleID: "201194", Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2024-6387"},
		Network: &ctis.NetworkLocation{Port: 22}}
}

func (u *upsertRig) count(t *testing.T, q string) int {
	t.Helper()
	var n int
	if err := u.db.QueryRow(q, u.tn.tenant.String()).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (u *upsertRig) callbackIDs() []shared.ID {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]shared.ID(nil), u.created...)
}

// The created callback (workflows, notifications) must only ever see ids of
// findings that exist.
func (u *upsertRig) assertCallbackIDsExist(t *testing.T) {
	t.Helper()
	for _, id := range u.callbackIDs() {
		var ok bool
		if err := u.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM findings WHERE id = $1)`, id.String()).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("created callback got finding id %s, which does not exist", id)
		}
	}
}

func TestFindingUpsert_ConcurrentIngestCreatesOnce(t *testing.T) {
	u := newUpsertRig(t)
	const n = 12
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created int
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out, err := u.svc.Ingest(context.Background(), u.agt, ingest.Input{Report: u.report(sshFinding())})
			if err != nil {
				t.Errorf("ingest: %v", err)
				return
			}
			mu.Lock()
			created += out.FindingsCreated
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if rows := u.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`); rows != 1 {
		t.Fatalf("finding rows = %d, want 1", rows)
	}
	if created != 1 {
		t.Errorf("sum(FindingsCreated) over %d concurrent ingests = %d, want 1", n, created)
	}
	if got := len(u.callbackIDs()); got != 1 {
		t.Errorf("created callback saw %d findings, want 1", got)
	}
	u.assertCallbackIDsExist(t)
}

func TestFindingUpsert_ConflictKeepsTicketLinksAndMetadata(t *testing.T) {
	u := newUpsertRig(t)
	if _, err := u.svc.Ingest(context.Background(), u.agt, ingest.Input{Report: u.report(sshFinding())}); err != nil {
		t.Fatal(err)
	}
	var id, fp, assetID string
	if err := u.db.QueryRow(`SELECT id, fingerprint, asset_id FROM findings WHERE tenant_id = $1`, u.tn.tenant.String()).Scan(&id, &fp, &assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := u.db.Exec(`UPDATE findings SET work_item_uris = '{https://jira.example/browse/SEC-1}',
		metadata = metadata || '{"user_note":"keep me"}' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	// What the loser of an ingest race does: insert a freshly built entity
	// with the same fingerprint.
	aid, _ := shared.IDFromString(assetID)
	f, err := vulnerability.NewFinding(u.tn.tenant, aid, vulnerability.FindingSourceExternal, "nessus", vulnerability.SeverityHigh, "OpenSSH regreSSHion")
	if err != nil {
		t.Fatal(err)
	}
	f.SetFingerprint(fp)
	f.SetMetadata("scanner_key", "v")
	res, err := u.frepo.CreateBatchWithResult(context.Background(), []*vulnerability.Finding{f})
	if err != nil {
		t.Fatal(err)
	}

	if res.Created != 0 || res.Updated != 1 || res.WasInserted(0) {
		t.Errorf("result: created=%d updated=%d inserted=%v, want 0/1/false", res.Created, res.Updated, res.WasInserted(0))
	}
	if f.ID().String() != id || res.IDs[0].String() != id {
		t.Errorf("in-memory id %s / reported id %s, want the persisted id %s", f.ID(), res.IDs[0], id)
	}
	var uris, note, scannerKey string
	if err := u.db.QueryRow(`SELECT array_to_string(work_item_uris, ','), COALESCE(metadata->>'user_note',''), COALESCE(metadata->>'scanner_key','')
		FROM findings WHERE id = $1`, id).Scan(&uris, &note, &scannerKey); err != nil {
		t.Fatal(err)
	}
	if uris != "https://jira.example/browse/SEC-1" {
		t.Errorf("work_item_uris = %q, want the ticket link kept", uris)
	}
	if note != "keep me" {
		t.Errorf("metadata.user_note = %q, want it kept", note)
	}
	if scannerKey != "v" {
		t.Errorf("metadata.scanner_key = %q, want a new key added", scannerKey)
	}
}

func TestFindingUpsert_RepeatedFindingInOneReportCreatesOnce(t *testing.T) {
	u := newUpsertRig(t)
	out, err := u.svc.Ingest(context.Background(), u.agt, ingest.Input{Report: u.report(sshFinding(), sshFinding())})
	if err != nil {
		t.Fatal(err)
	}
	if rows := u.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`); rows != 1 {
		t.Fatalf("finding rows = %d, want 1", rows)
	}
	if out.FindingsCreated != 1 {
		t.Errorf("FindingsCreated = %d, want 1", out.FindingsCreated)
	}
	if len(out.Errors) > 0 {
		t.Errorf("errors: %v", out.Errors)
	}
	if got := len(u.callbackIDs()); got != 1 {
		t.Errorf("created callback saw %d findings, want 1", got)
	}
	u.assertCallbackIDsExist(t)
}

// lostRaceRepo answers every fingerprint check with "not stored yet": the
// state an ingest sees when a concurrent ingest inserts the same finding
// between this ingest's check and its insert. It makes that race
// deterministic.
type lostRaceRepo struct {
	*postgres.FindingRepository
}

func (lostRaceRepo) CheckFingerprintsExist(_ context.Context, _ shared.ID, fps []string) (map[string]bool, error) {
	out := make(map[string]bool, len(fps))
	for _, fp := range fps {
		out[fp] = false
	}
	return out, nil
}

func TestFindingUpsert_LosingTheRaceIsNotACreation(t *testing.T) {
	u := newUpsertRig(t)
	if _, err := u.svc.Ingest(context.Background(), u.agt, ingest.Input{Report: u.report(sshFinding())}); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := u.db.QueryRow(`SELECT id FROM findings WHERE tenant_id = $1`, u.tn.tenant.String()).Scan(&id); err != nil {
		t.Fatal(err)
	}

	db := &postgres.DB{DB: u.db}
	loser := ingest.NewService(
		postgres.NewAssetRepository(db), lostRaceRepo{u.frepo},
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	var seen []shared.ID
	loser.SetFindingCreatedCallback(func(_ context.Context, _ shared.ID, fs []*vulnerability.Finding) {
		for _, f := range fs {
			seen = append(seen, f.ID())
		}
	})
	out, err := loser.Ingest(context.Background(), u.agt, ingest.Input{Report: u.report(sshFinding())})
	if err != nil {
		t.Fatal(err)
	}

	if rows := u.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1`); rows != 1 {
		t.Fatalf("finding rows = %d, want 1", rows)
	}
	if out.FindingsCreated != 0 {
		t.Errorf("FindingsCreated = %d for a finding another ingest created, want 0", out.FindingsCreated)
	}
	if len(seen) != 0 {
		t.Errorf("created callback ran for %v, want no call (the finding %s already existed)", seen, id)
	}
}
