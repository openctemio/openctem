package routes

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/contract/ctlookup"

	"github.com/openctemio/openctem/server/internal/app/certmonitor"
	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/app/lookupjob"
	"github.com/openctemio/openctem/server/internal/app/sensor"
	infrahttp "github.com/openctemio/openctem/server/internal/infra/http"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/crypto"
	lookupjobdom "github.com/openctemio/openctem/server/pkg/domain/lookupjob"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/jobsign"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/sensorkey"
	protov2 "github.com/openctemio/openctem/server/pkg/sensorproto/v2"
)

// recordingSigner signs nothing and records every statement.
type recordingSigner struct {
	mu  sync.Mutex
	sts []jobsign.Statement
}

func (s *recordingSigner) SignJob(_ context.Context, st jobsign.Statement) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sts = append(s.sts, st)
	return json.RawMessage(`{"payloadType":"application/vnd.openctem.job.v1+json"}`), nil
}

// TestLookupJobRoutes (SECURITY): a CT lookup for organization A is
// offered only to a platform (instance-scope) sensor reporting lookup.ct@1,
// signed for organization A, the instance scope and that sensor; an
// organization's sensor is refused on both routes, even one reporting the
// capability; another platform sensor cannot answer a job it did not claim;
// a job is answered once; organization B cannot read A's job; and the CT
// source turns the answer into names under the queried domain only.
func TestLookupJobRoutes(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping lookup job route test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()

	sensorRepo := postgres.NewSensorRepository(db)
	sensorSvc := sensor.NewSensorService(sensorRepo, nil, log)
	sensorSvc.SetAPIKeyRepository(postgres.NewSensorAPIKeyRepository(db))
	ingestSvc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensorRepo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	ctl := handler.NewSensorControlV2Handler(handler.NewIngestHandler(ingestSvc, sensorSvc, log), nil, nil, log)
	repo := postgres.NewLookupJobRepository(db)
	signer := &recordingSigner{}
	svc := lookupjob.NewService(lookupjob.Config{Signer: signer, Timeout: 20 * time.Second, Poll: 50 * time.Millisecond}, repo, log)
	ctl.SetLookupJobs(handler.NewLookupJobHandler(svc, log))
	receiver := ingest.NewV2Receiver(postgres.NewIngestReportRepository(db), postgres.NewIngestJobRepository(db),
		postgres.NewIngestJobRepository(db), postgres.NewCommandRepository(db), protov2.DefaultLimits(), 100, log)
	receiver.SetPayloadSealer(testSegmentSealer(t))
	router := infrahttp.NewChiRouter()
	registerSensorV2Routes(router, handler.NewSensorResultsV2Handler(receiver, sensorSvc, log), ctl, nil, log)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	online := func(id shared.ID) {
		if _, err := sqldb.ExecContext(ctx, `UPDATE sensors SET health = 'online', last_seen_at = now() WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	platformSensor := func() (string, *sensordom.Sensor) {
		key, err := sensorkey.New(sensorkey.PrefixSensorKey)
		if err != nil {
			t.Fatal(err)
		}
		s, err := sensordom.NewSensor(shared.NewID(), "ct-"+shared.NewID().String()[24:], sensordom.SensorTypeWorker, "", []string{ctlookup.Capability}, sensordom.ExecutionModeDaemon)
		if err != nil {
			t.Fatal(err)
		}
		s.Scope, s.TenantID = sensordom.ScopeInstance, nil
		s.SetAPIKey(crypto.HashTokenPeppered(key, ""), sensorkey.DisplayPrefix(key))
		if err := sensorRepo.Create(ctx, s); err != nil {
			t.Fatalf("create platform sensor: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, s.ID.String())
		})
		return key, s
	}
	newTenant := func() shared.ID {
		id := shared.NewID()
		if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "ct-"+id.String()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM sensor_lookup_jobs WHERE tenant_id = $1`, id.String())
			_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM sensors WHERE tenant_id = $1`, id.String())
			_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
		})
		return id
	}
	do := func(key, method, path string, body []byte) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, method, srv.URL+protov2.PathPrefix+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("User-Agent", "openctem-sdk-go/0.51.0 (openctemio-sensor/0.40.0)")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	tenantA, tenantB := newTenant(), newTenant()
	ctKey, ctSensor := platformSensor()
	otherKey, other := platformSensor()

	// No sensor is reachable yet: CT lookups are unavailable.
	if svc.Available(ctx, ctlookup.Capability) {
		t.Fatal("available before any platform sensor is online")
	}
	// An organization's sensor reporting the capability does not make CT
	// available and is refused on both routes.
	org, err := sensorSvc.CreateSensor(ctx, sensor.CreateSensorInput{TenantID: tenantA.String(), Name: "org-ct", Type: "worker",
		Capabilities: []string{ctlookup.Capability}, ExecutionMode: "daemon"})
	if err != nil {
		t.Fatal(err)
	}
	online(org.Sensor.ID)
	if svc.Available(ctx, ctlookup.Capability) {
		t.Fatal("an organization's sensor made CT lookups available")
	}
	if code, _ := do(org.APIKey, http.MethodGet, "/lookups/next", nil); code != http.StatusForbidden {
		t.Fatalf("organization sensor next: %d, want 403", code)
	}
	online(ctSensor.ID)
	online(other.ID)
	if !svc.Available(ctx, ctlookup.Capability) {
		t.Fatal("not available with an online platform sensor")
	}
	if code, _ := do(ctKey, http.MethodGet, "/lookups/next", nil); code != http.StatusNoContent {
		t.Fatalf("idle next: %d, want 204", code)
	}

	// Organization A asks; the CT source of the platform asks through the
	// lookup job.
	type answer struct {
		out ctlookup.Output
		err error
	}
	done := make(chan answer, 1)
	go func() {
		out, err := certmonitor.SensorSource{Jobs: svc}.Lookup(ctx, tenantA, "example.com")
		done <- answer{out, err}
	}()
	var next lookupjob.Next
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, raw := do(ctKey, http.MethodGet, "/lookups/next", nil)
		if code == http.StatusOK {
			if err := json.Unmarshal(raw, &next); err != nil {
				t.Fatal(err)
			}
			break
		}
		if code != http.StatusNoContent || time.Now().After(deadline) {
			t.Fatalf("next: %d %s", code, raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
	signer.mu.Lock()
	st := signer.sts[len(signer.sts)-1]
	signer.mu.Unlock()
	if st.TenantID != tenantA.String() || st.SensorID != ctSensor.ID.String() || st.SensorScope != jobsign.SensorScopeInstance ||
		st.CommandType != jobsign.CommandTypeLookup || st.Tool != ctlookup.Tool || st.CommandID != next.ID ||
		len(st.Targets) != 1 || st.Targets[0] != "example.com" || st.PayloadSHA256 != jobsign.PayloadDigest(next.Payload) {
		t.Fatalf("statement %+v for job %s", st, next.ID)
	}
	var p struct {
		Scanner    string         `json:"scanner"`
		Targets    []string       `json:"targets"`
		Capability string         `json:"capability"`
		Input      ctlookup.Input `json:"input"`
	}
	if err := json.Unmarshal(next.Payload, &p); err != nil || p.Scanner != ctlookup.Tool || p.Capability != ctlookup.Capability || p.Input.Domain != "example.com" {
		t.Fatalf("payload %s: %v", next.Payload, err)
	}
	jobID, _ := shared.IDFromString(next.ID)

	// Organization B never sees A's job.
	if _, err := repo.Get(ctx, tenantB, jobID); !errors.Is(err, lookupjobdom.ErrNotFound) {
		t.Fatalf("tenant B read tenant A's job: %v", err)
	}
	// Neither another platform sensor nor an organization's sensor can
	// answer it.
	out := ctlookup.Output{
		Records: []ctlookup.Record{{Source: ctlookup.SourceCRTSH, EntryID: "1",
			DNSNames: []string{"www.example.com", "victim.example.org", "*.dev.example.com"}, NotAfter: "2027-01-01T00:00:00Z"}},
		SourceStatus: []ctlookup.SourceStatus{{Source: ctlookup.SourceCRTSH, State: ctlookup.StateOK}},
	}
	ob, _ := json.Marshal(out)
	res, _ := json.Marshal(map[string]any{"output": json.RawMessage(ob)})
	if code, _ := do(otherKey, http.MethodPost, "/lookups/"+next.ID+"/done", res); code != http.StatusNotFound {
		t.Fatalf("another platform sensor answered: %d", code)
	}
	if code, _ := do(org.APIKey, http.MethodPost, "/lookups/"+next.ID+"/done", res); code != http.StatusForbidden {
		t.Fatalf("an organization's sensor answered: %d", code)
	}
	if code, _ := do(ctKey, http.MethodPost, "/lookups/"+next.ID+"/done", []byte(`{"output":{},"tenant_id":"x"}`)); code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown field accepted: %d", code)
	}
	if code, b := do(ctKey, http.MethodPost, "/lookups/"+next.ID+"/done", res); code != http.StatusNoContent {
		t.Fatalf("done: %d %s", code, b)
	}
	if code, _ := do(ctKey, http.MethodPost, "/lookups/"+next.ID+"/done", res); code != http.StatusNotFound {
		t.Fatalf("answered twice: %d", code)
	}
	a := <-done
	if a.err != nil {
		t.Fatal(a.err)
	}
	clean, rep, err := ctlookup.Validate("example.com", a.out)
	if err != nil || rep.DroppedNames != 1 || len(clean.Records) != 1 ||
		strings.Join(clean.Records[0].DNSNames, ",") != "www.example.com,*.dev.example.com" {
		t.Fatalf("answer %+v %+v %v", clean, rep, err)
	}
	// The question is gone once answered.
	if _, err := repo.Get(ctx, tenantA, jobID); !errors.Is(err, lookupjobdom.ErrNotFound) {
		t.Fatalf("answered job kept: %v", err)
	}
}
