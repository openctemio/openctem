package routes

// The job signer's scope ledger end to end (RFC-040 §5.6 points 4 and 5,
// docs/architecture/job-signing.md "Scope ledger"), over the real claim
// routes, a migrated database, the real signer on a Unix socket and the
// scope service feeding it. The claim harness has no API-side scope
// re-check, so a command reaches the signer as a row written straight into
// the database would: only the signer's ledger stands in the way.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	signerclient "github.com/openctemio/openctem/api/internal/infra/signer"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func (h *ctlHarness) newScanCommand(tenantID, payload string) string {
	h.t.Helper()
	c, err := h.cmds.Create(context.Background(), command.CreateInput{TenantID: tenantID,
		Type: "scan", Priority: "normal", Payload: json.RawMessage(payload), ExpiresIn: 3600})
	if err != nil {
		h.t.Fatalf("create command: %v", err)
	}
	return c.ID.String()
}

func (h *ctlHarness) commandError(id string) string {
	h.t.Helper()
	var msg *string
	if err := h.db.QueryRowContext(context.Background(), `SELECT error_message FROM commands WHERE id = $1`, id).Scan(&msg); err != nil {
		h.t.Fatalf("read command: %v", err)
	}
	if msg == nil {
		return ""
	}
	return *msg
}

func (h *ctlHarness) claimIDs(key string) []string {
	h.t.Helper()
	resp, raw := h.call(key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	var ids []string
	for _, c := range decodeAs[wireCommandList](h.t, raw).Commands {
		if len(c.SignedJob) == 0 {
			h.t.Fatalf("unsigned command handed out: %s", raw)
		}
		ids = append(ids, c.ID)
	}
	return ids
}

func TestSignerLedger_DatabaseCommandsOutsideTheLedgerAreNotSigned(t *testing.T) {
	client, _ := realSigner(t)
	h := newCtlHarness(t, command.WithJobSigner(client))
	s := h.newVerifiedSensor(h.tenantID, "ledger", []string{"nuclei", "semgrep"}, nil, 10)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	scopeSvc := scope.NewService(postgres.NewScopeTargetRepository(db), postgres.NewScopeExclusionRepository(db),
		postgres.NewAssetRepository(db), logger.NewNop())
	scopeSvc.SetLedger(client)

	// Nobody approved anything yet: a command row naming any target fails
	// at claim with the signer's reason, and is not handed out.
	rogue := h.newScanCommand(h.tenantID, `{"scanner":"nuclei","targets":["app.example.com"]}`)
	if ids := h.claimIDs(s.key); len(ids) != 0 {
		t.Fatalf("handed out %v", ids)
	}
	if st, _, _ := h.commandState(rogue); st != "failed" || !strings.HasPrefix(h.commandError(rogue), command.FailureSignerRefused) ||
		!strings.Contains(h.commandError(rogue), "out_of_ledger") {
		t.Fatalf("rogue command %s: %q", st, h.commandError(rogue))
	}

	// The scope service puts an entry into effect: the signer accepts the
	// widening before the row is saved, and signs inside it.
	if _, err := scopeSvc.CreateTarget(ctx, scope.CreateTargetInput{TenantID: h.tenantID, TargetType: "domain",
		Pattern: "*.example.com", MaxTier: "t1"}); err != nil {
		t.Fatal(err)
	}
	if st, err := client.LedgerStatus(ctx); err != nil || st.Mode != "enforce" || len(st.Tenants) != 1 || st.Tenants[0] != h.tenantID {
		t.Fatalf("ledger status %+v %v", st, err)
	}
	inScope := h.newScanCommand(h.tenantID, `{"scanner":"nuclei","targets":["app.example.com","https://example.com/login"]}`)
	outScope := h.newScanCommand(h.tenantID, `{"scanner":"nuclei","targets":["app.example.com","victim.example.org"]}`)
	ids := h.claimIDs(s.key)
	if len(ids) != 1 || ids[0] != inScope {
		t.Fatalf("claimed %v, want only %s", ids, inScope)
	}
	if st, _, _ := h.commandState(outScope); st != "failed" {
		t.Fatalf("out-of-scope command %s", st)
	}

	// An exclusion approved later binds at once.
	userA, userB := shared.NewID().String(), shared.NewID().String()
	x, err := scopeSvc.CreateExclusion(ctx, scope.CreateExclusionInput{TenantID: h.tenantID, ExclusionType: "domain",
		Pattern: "prod.example.com", Reason: "production", CreatedBy: userA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scopeSvc.ApproveExclusion(ctx, x.ID().String(), h.tenantID, userB); err != nil {
		t.Fatal(err)
	}
	prod := h.newScanCommand(h.tenantID, `{"scanner":"nuclei","targets":["prod.example.com"]}`)
	if ids := h.claimIDs(s.key); len(ids) != 0 {
		t.Fatalf("excluded target handed out: %v", ids)
	}
	if !strings.Contains(h.commandError(prod), "target_excluded") {
		t.Fatalf("excluded command: %q", h.commandError(prod))
	}

	// A row written straight into the database widens nothing: the signer
	// never saw it.
	if _, err := h.db.ExecContext(ctx, `
		INSERT INTO scope_targets (id, tenant_id, target_type, pattern, description, status, created_by, created_at, updated_at)
		VALUES ($1, $2, 'domain', '*.victim.example.org', '', 'active', 'attacker', now(), now())`,
		shared.NewID().String(), h.tenantID); err != nil {
		t.Fatal(err)
	}
	victim := h.newScanCommand(h.tenantID, `{"scanner":"nuclei","targets":["app.victim.example.org"]}`)
	if ids := h.claimIDs(s.key); len(ids) != 0 {
		t.Fatalf("DB-written scope signed: %v", ids)
	}
	if !strings.Contains(h.commandError(victim), "out_of_ledger") {
		t.Fatalf("victim command: %q", h.commandError(victim))
	}
	// ... and the periodic sync does not take it into the ledger either
	// (it narrows only: the row is counted as diverged).
	if err := scopeSvc.SyncLedger(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := scopeSvc.LedgerSnapshot(ctx, h.tenantID)
	if err != nil || len(snap.Entries) != 2 {
		t.Fatalf("snapshot %+v %v", snap, err)
	}
	if res, err := client.SyncLedger(ctx, snap); err != nil || res.Narrowed != 0 || res.Diverged != 1 {
		t.Fatalf("sync %+v %v", res, err)
	}
	victim2 := h.newScanCommand(h.tenantID, `{"scanner":"nuclei","targets":["www.victim.example.org"]}`)
	if ids := h.claimIDs(s.key); len(ids) != 0 {
		t.Fatalf("synced DB-written scope signed: %v", ids)
	}
	if st, _, _ := h.commandState(victim2); st != "failed" {
		t.Fatalf("victim2 %s", st)
	}
}

func TestSignerLedger_WideningFailsWhenTheSignerDoesNotAccept(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	scopeSvc := scope.NewService(postgres.NewScopeTargetRepository(db), postgres.NewScopeExclusionRepository(db),
		postgres.NewAssetRepository(db), logger.NewNop())
	dir, err := os.MkdirTemp("", "sl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	scopeSvc.SetLedger(signerclient.NewClient(filepath.Join(dir, "absent.sock"), time.Second))

	_, err = scopeSvc.CreateTarget(ctx, scope.CreateTargetInput{TenantID: h.tenantID, TargetType: "domain", Pattern: "*.example.net"})
	if !errors.Is(err, scope.ErrLedgerUnavailable) {
		t.Fatalf("widening with the signer down: %v", err)
	}
	var n int
	if err := h.db.QueryRowContext(ctx, `SELECT count(*) FROM scope_targets WHERE tenant_id = $1 AND pattern = '*.example.net'`,
		h.tenantID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the entry was saved without the signer: %d %v", n, err)
	}
}
