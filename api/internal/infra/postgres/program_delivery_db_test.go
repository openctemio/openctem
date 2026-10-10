package postgres

// Outbound delivery of private program events (RFC-065 §15.4) against a
// migrated database: the routing decision for each kind of subject, program
// channels (tenant-bound), the owner opt-in, and the EASM digest. Requires
// DATABASE_URL.

import (
	"context"
	"errors"
	"strings"
	"testing"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestProgramDelivery(t *testing.T) {
	fx := seedPrivateProgram(t)
	ctx := context.Background()
	db, tenant, other := fx.db, fx.tenant, fx.other
	repo := NewProgramDeliveryRepository(fx.pdb)

	var programID shared.ID
	var raw string
	if err := db.QueryRow(`SELECT id FROM bounty_programs WHERE tenant_id = $1`, tenant.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	programID, _ = shared.IDFromString(raw)

	integ := func(tid shared.ID, name, category string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.Exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, status)
			VALUES ($1, $2, $3, $4, 'webhook', 'connected')`, id.String(), tid.String(), name, category); err != nil {
			t.Fatal(err)
		}
		return id
	}
	orgSlack := integ(tenant, "org-wide", "notification")
	progHook := integ(tenant, "program-hook", "notification")
	scm := integ(tenant, "github", "scm")
	foreignHook := integ(other, "foreign", "notification")

	resolve := func(tid shared.ID, s bp.DeliverySubject) bp.Delivery {
		t.Helper()
		d, err := repo.Resolve(ctx, tid, s)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	findingOf := func(id shared.ID) bp.DeliverySubject { return bp.DeliverySubject{FindingIDs: []shared.ID{id}} }

	t.Run("program-only asset: suppressed from org-wide integrations", func(t *testing.T) {
		d := resolve(tenant, findingOf(fx.hiddenFinding))
		if !d.IsRestricted() || d.Allows(orgSlack) || d.Allows(progHook) {
			t.Fatalf("hidden finding delivery = %+v", d)
		}
		if len(d.Programs) != 1 || d.Programs[0].ID != programID || d.Programs[0].Tag != "program:acme:priv" {
			t.Fatalf("programs = %+v", d.Programs)
		}
		if got := d.Scrub(orgSlack, "New finding for "+d.Programs[0].Name); strings.Contains(got, "Priv") {
			t.Fatalf("scrub = %q", got)
		}
	})

	t.Run("program channel: tenant-bound, notification integrations only", func(t *testing.T) {
		member := fx.member
		if err := repo.AttachChannel(ctx, tenant, programID, progHook, &member); err != nil {
			t.Fatal(err)
		}
		if err := repo.AttachChannel(ctx, tenant, programID, progHook, &member); err != nil {
			t.Fatalf("attach is idempotent: %v", err)
		}
		for name, c := range map[string]struct{ tid, iid shared.ID }{
			"another tenant's integration":              {tenant, foreignHook},
			"a non-notification integration":            {tenant, scm},
			"the program from another tenant's context": {other, foreignHook},
		} {
			if err := repo.AttachChannel(ctx, c.tid, programID, c.iid, nil); !errors.Is(err, bp.ErrChannelNotFound) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		d := resolve(tenant, findingOf(fx.hiddenFinding))
		if !d.Allows(progHook) || d.Allows(orgSlack) {
			t.Fatalf("after attach: %+v", d)
		}
		if got := d.Scrub(progHook, d.Programs[0].Name); got != d.Programs[0].Name {
			t.Fatalf("program channel scrubbed its own program: %q", got)
		}
		ch, err := repo.Channels(ctx, tenant, programID)
		if err != nil || len(ch) != 1 || ch[0].IntegrationID != progHook || ch[0].CreatedBy == nil || *ch[0].CreatedBy != member {
			t.Fatalf("channels = %+v %v", ch, err)
		}
		if ch, _ := repo.Channels(ctx, other, programID); len(ch) != 0 {
			t.Fatal("another tenant lists the program's channels")
		}
	})

	t.Run("asset, exposure and approval subjects resolve to the same asset", func(t *testing.T) {
		if !resolve(tenant, bp.DeliverySubject{AssetIDs: []shared.ID{fx.hidden}}).IsRestricted() {
			t.Fatal("asset subject")
		}
		var approval string
		if err := db.QueryRow(`INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status)
			VALUES ($1, $2, 'false_positive') RETURNING id`, tenant.String(), fx.hiddenFinding.String()).Scan(&approval); err != nil {
			t.Fatal(err)
		}
		aid, _ := shared.IDFromString(approval)
		if !resolve(tenant, bp.DeliverySubject{ApprovalIDs: []shared.ID{aid}}).IsRestricted() {
			t.Fatal("approval subject")
		}
		// A batch naming the hidden and the own asset is restricted as a whole.
		if !resolve(tenant, bp.DeliverySubject{AssetIDs: []shared.ID{fx.own, fx.hidden}}).IsRestricted() {
			t.Fatal("batch subject")
		}
	})

	t.Run("shared and own assets: normal routing, program name scrubbed", func(t *testing.T) {
		d := resolve(tenant, bp.DeliverySubject{AssetIDs: []shared.ID{fx.shared1}})
		if d.IsRestricted() || !d.Allows(orgSlack) {
			t.Fatalf("shared asset restricted: %+v", d)
		}
		if len(d.Programs) != 1 || d.Scrub(orgSlack, "tag program:acme:priv") != "tag "+bp.ScrubbedProgram {
			t.Fatalf("shared asset scrub: %+v", d.Programs)
		}
		own := resolve(tenant, findingOf(fx.ownFinding))
		if own.IsRestricted() || len(own.Programs) != 0 {
			t.Fatalf("own finding: %+v", own)
		}
	})

	t.Run("cross-tenant: ids of another tenant match nothing", func(t *testing.T) {
		d := resolve(other, bp.DeliverySubject{FindingIDs: []shared.ID{fx.hiddenFinding}, AssetIDs: []shared.ID{fx.hidden}})
		if d.IsRestricted() || len(d.Programs) != 0 {
			t.Fatalf("other tenant: %+v", d)
		}
		got, err := repo.RestrictedAssets(ctx, other, []shared.ID{fx.hidden})
		if err != nil || len(got) != 0 {
			t.Fatalf("other tenant restricted = %v %v", got, err)
		}
	})

	t.Run("restricted assets batch", func(t *testing.T) {
		got, err := repo.RestrictedAssets(ctx, tenant, []shared.ID{fx.hidden, fx.shared1, fx.own, fx.foreign})
		if err != nil || len(got) != 1 || !got[fx.hidden] {
			t.Fatalf("restricted = %v %v", got, err)
		}
	})

	t.Run("owner opt-in delivers org-wide", func(t *testing.T) {
		if err := repo.SetOrgChannels(ctx, tenant, programID, true); err != nil {
			t.Fatal(err)
		}
		if on, _ := repo.OrgChannels(ctx, tenant, programID); !on {
			t.Fatal("opt-in not stored")
		}
		d := resolve(tenant, findingOf(fx.hiddenFinding))
		if d.IsRestricted() || !d.Allows(orgSlack) {
			t.Fatalf("opted in: %+v", d)
		}
		// The name is still scrubbed for org-wide destinations.
		if len(d.Programs) != 1 {
			t.Fatalf("opted in programs: %+v", d.Programs)
		}
		if err := repo.SetOrgChannels(ctx, other, programID, true); !errors.Is(err, bp.ErrNotFound) {
			t.Fatalf("another tenant sets the opt-in: %v", err)
		}
		if err := repo.SetOrgChannels(ctx, tenant, programID, false); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("EASM: a restricted exposure is not folded into the digest", func(t *testing.T) {
		alerts := NewEASMAlerter(fx.pdb)
		writer := NewEASMExposureWriter(fx.pdb, alerts)
		ev := func(assetID shared.ID, title string) *exposure.ExposureEvent {
			e, err := exposure.NewExposureEvent(tenant, exposure.EventTypeDanglingCNAME, exposure.SeverityLow, title, "easm_dns",
				map[string]any{"domain": title})
			if err != nil {
				t.Fatal(err)
			}
			e.SetAssetID(&assetID)
			return e
		}
		if err := writer.BulkUpsert(ctx, []*exposure.ExposureEvent{
			ev(fx.hidden, "Dangling CNAME: app.p"+fx.suffix+".example"),
			ev(fx.own, "Dangling CNAME: www.own"+fx.suffix+".example"),
		}); err != nil {
			t.Fatal(err)
		}
		var immediateID string
		if err := db.QueryRow(`SELECT aggregate_id FROM notification_outbox
			WHERE tenant_id = $1 AND aggregate_type = 'exposure'`, tenant.String()).Scan(&immediateID); err != nil {
			t.Fatalf("restricted exposure not sent on its own: %v", err)
		}
		var digestCount int
		if err := db.QueryRow(`SELECT COALESCE((metadata->>'count')::int, -1) FROM notification_outbox
			WHERE tenant_id = $1 AND aggregate_type = 'easm_digest'`, tenant.String()).Scan(&digestCount); err != nil {
			t.Fatal(err)
		}
		if digestCount != 1 {
			t.Fatalf("digest count = %d, want 1 (own exposure only)", digestCount)
		}
		eid, _ := shared.IDFromString(immediateID)
		if !resolve(tenant, bp.DeliverySubject{ExposureIDs: []shared.ID{eid}}).IsRestricted() {
			t.Fatal("exposure subject not restricted")
		}
	})

	t.Run("detach", func(t *testing.T) {
		if err := repo.DetachChannel(ctx, other, programID, progHook); !errors.Is(err, bp.ErrChannelNotFound) {
			t.Fatalf("another tenant detaches: %v", err)
		}
		if err := repo.DetachChannel(ctx, tenant, programID, progHook); err != nil {
			t.Fatal(err)
		}
		if resolve(tenant, findingOf(fx.hiddenFinding)).Allows(progHook) {
			t.Fatal("detached channel still receives")
		}
	})
}
