package audit_test

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/audit/chainclassify"
	"github.com/openctemio/openctem/api/internal/app/audit/chainclassify/chaintest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The admin console rebaseline (RebaselineChainIfExplained) re-runs the
// classification in the walk that re-signs, and refuses unless every break is
// explained and the chain is the one the administrator reviewed. These tests
// seed the shapes the historical hashing defects left on live.
//
// DB-gated: DATABASE_URL must name a migrated *_test database.

func TestClassifyChain_CountsLegacyShapes(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenant, 6)
	if _, err := chaintest.Resign(ctx, db.DB, tenant.String(),
		chaintest.Current, chaintest.Legacy, chaintest.Pre79, chaintest.Legacy, chaintest.Current, chaintest.Pre79); err != nil {
		t.Fatal(err)
	}

	rep, err := svc.ClassifyChain(ctx, tenant)
	if err != nil {
		t.Fatalf("ClassifyChain: %v", err)
	}
	want := chainclassify.Counts{Verifies: 2, LegacyTruncate: 2, PreHashReduction: 2}
	if rep.Counts != want || rep.Total != 6 || rep.Breaks != 4 || !rep.RebaselineAllowed() {
		t.Fatalf("report = %+v, want counts %+v", rep, want)
	}
	for _, s := range rep.Samples {
		if s.Class == chainclassify.PreHashReduction && s.OffsetNS != chaintest.Pre79OffsetNS {
			t.Fatalf("recovered offset %d, want %d", s.OffsetNS, chaintest.Pre79OffsetNS)
		}
	}
	// Classifying writes nothing, so it is stable.
	again, err := svc.ClassifyChain(ctx, tenant)
	if err != nil || again.Fingerprint != rep.Fingerprint {
		t.Fatalf("a second classification must give the same fingerprint (err=%v)", err)
	}
}

func TestRebaselineChainIfExplained_ReSignsAnExplainedChain(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, user := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenant, 5)
	if _, err := chaintest.Resign(ctx, db.DB, tenant.String(),
		chaintest.Legacy, chaintest.Current, chaintest.Pre79, chaintest.Legacy, chaintest.Current); err != nil {
		t.Fatal(err)
	}
	if v, err := svc.VerifyChain(ctx, tenant, 0); err != nil || v.OK {
		t.Fatalf("precondition: the seeded chain must not verify (ok=%v err=%v)", v != nil && v.OK, err)
	}
	rep, err := svc.ClassifyChain(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}

	res, after, err := svc.RebaselineChainIfExplained(ctx, tenant, rep.Fingerprint,
		auditapp.AuditContext{ActorEmail: "platform-admin:ops@example.test"}, user.String())
	if err != nil {
		t.Fatalf("RebaselineChainIfExplained: %v", err)
	}
	if res.EntriesTotal != 5 || res.EntriesRewritten == 0 || after == nil || after.Fingerprint != rep.Fingerprint {
		t.Fatalf("result %+v, classification %+v", res, after)
	}
	v, err := svc.VerifyChain(ctx, tenant, 0)
	if err != nil || !v.OK || len(v.Breaks) != 0 {
		t.Fatalf("after rebaseline the chain must verify with 0 breaks: %+v err=%v", v, err)
	}
	// The archive names the administrator's account; the tenant log carries the
	// success event signed onto the re-signed chain (Total = 5 + 1).
	if v.Total != 6 {
		t.Fatalf("verified %d entries, want 6 (5 + the rebaseline event)", v.Total)
	}
	if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_chain_rebaselines WHERE id = $1 AND actor_id = $2`,
		res.RebaselineID, user.String()); n != 1 {
		t.Fatalf("archive row with the actor: %d", n)
	}
	if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'audit.chain_rebaselined'
		AND result = 'success' AND actor_email = 'platform-admin:ops@example.test'
		AND metadata->>'classification_fingerprint' = $2`, tenant.String(), rep.Fingerprint); n != 1 {
		t.Fatalf("tenant audit event for the rebaseline: %d", n)
	}
}

func TestRebaselineChainIfExplained_RefusesUnexplained(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, user := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenant, 4)
	if _, err := chaintest.Resign(ctx, db.DB, tenant.String(),
		chaintest.Legacy, chaintest.Bogus, chaintest.Current, chaintest.Current); err != nil {
		t.Fatal(err)
	}
	rep, err := svc.ClassifyChain(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts.Unexplained != 1 || rep.RebaselineAllowed() {
		t.Fatalf("classification must flag the bogus row: %+v", rep.Counts)
	}
	before := readChain(ctx, t, db, tenant)

	_, refused, err := svc.RebaselineChainIfExplained(ctx, tenant, rep.Fingerprint, auditapp.AuditContext{}, user.String())
	if !errors.Is(err, auditapp.ErrChainUnexplained) {
		t.Fatalf("err = %v, want ErrChainUnexplained", err)
	}
	if refused == nil || refused.Counts.Unexplained != 1 {
		t.Fatalf("the refusal must carry the classification: %+v", refused)
	}
	assertChainUnchanged(ctx, t, db, tenant.String(), before)
}

func TestRebaselineChainIfExplained_RefusesAChangedChain(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, user := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenant, 3)
	if _, err := chaintest.Resign(ctx, db.DB, tenant.String(), chaintest.Legacy); err != nil {
		t.Fatal(err)
	}
	reviewed, err := svc.ClassifyChain(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}

	// The organization keeps working after the administrator reviewed it.
	logTenantEvents(ctx, t, svc, tenant, 1)
	before := readChain(ctx, t, db, tenant)

	_, _, err = svc.RebaselineChainIfExplained(ctx, tenant, reviewed.Fingerprint, auditapp.AuditContext{}, user.String())
	if !errors.Is(err, auditapp.ErrChainFingerprintMismatch) {
		t.Fatalf("err = %v, want ErrChainFingerprintMismatch", err)
	}
	assertChainUnchanged(ctx, t, db, tenant.String(), before)

	if _, _, err := svc.RebaselineChainIfExplained(ctx, tenant, "", auditapp.AuditContext{}, user.String()); err == nil {
		t.Fatal("an empty fingerprint must be refused")
	}
}

// assertChainUnchanged checks that the rows that existed before a refused
// rebaseline still carry their hashes (the refusal itself appends one event).
func assertChainUnchanged(ctx context.Context, t *testing.T, db *postgres.DB, tenantID string, before []chainRow) {
	t.Helper()
	for _, r := range before {
		var prev, hash string
		if err := db.QueryRowContext(ctx, `SELECT prev_hash, hash FROM audit_log_chain WHERE audit_log_id = $1`,
			r.AuditLogID).Scan(&prev, &hash); err != nil {
			t.Fatalf("read row %s: %v", r.AuditLogID, err)
		}
		if prev != r.PrevHash || hash != r.Hash {
			t.Fatalf("row at position %d was rewritten by a refused rebaseline", r.Position)
		}
	}
	if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_chain_rebaselines WHERE tenant_id = $1`, tenantID); n != 0 {
		t.Fatalf("a refused rebaseline archived %d rows", n)
	}
	if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'audit.chain_rebaselined'
		AND result = 'failure'`, tenantID); n != 1 {
		t.Fatalf("the refusal must be audited on the tenant log once, got %d", n)
	}
}
