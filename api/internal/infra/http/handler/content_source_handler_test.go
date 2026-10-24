package handler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	cs "github.com/openctemio/openctem/api/pkg/domain/contentsource"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SECURITY: an organization sees a platform source only as a projection: no
// URL, credential, CA, schedule, webhook or error text (it can name internal
// hosts). Its own source never carries the token, only that one is set.
func TestContentSourceResponse_Projection(t *testing.T) {
	tenant := shared.NewID()
	now := time.Now()
	platform := &cs.Source{
		ID: shared.NewID(), Scope: cs.ScopePlatform, Slug: "central", Name: "Central", Kind: cs.KindSemgrepRules,
		Origin: cs.OriginGit, URL: "https://git.internal.example/central/rules.git", Ref: "main",
		AuthUsername: "svc", CredentialEncrypted: "sealed-secret", CredentialHint: "wxyz", CredentialUpdatedAt: &now,
		CAPEM: "-----BEGIN CERTIFICATE-----", SyncIntervalMin: 60, WebhookSecretHash: strings.Repeat("a", 64),
		LastSyncStatus: cs.SyncFailed, LastSyncError: "dial tcp 10.0.0.5:443", Availability: cs.AvailabilityDefaultOn,
	}
	raw, _ := json.Marshal(toContentSourceResponse(platform, tenant))
	body := string(raw)
	for _, leak := range []string{"git.internal.example", "sealed-secret", "wxyz", "svc", "BEGIN CERTIFICATE", "10.0.0.5", `"webhook"`, `"sync_interval_minutes"`} {
		if strings.Contains(body, leak) {
			t.Errorf("platform projection leaks %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, `"sync_health":"degraded"`) || !strings.Contains(body, `"editable":false`) || !strings.Contains(body, `"namespace":"@central"`) {
		t.Errorf("platform projection: %s", body)
	}

	own := *platform
	own.Scope, own.TenantID, own.Availability = cs.ScopeTenant, &tenant, ""
	raw, _ = json.Marshal(toContentSourceResponse(&own, tenant))
	body = string(raw)
	if strings.Contains(body, "sealed-secret") || strings.Contains(body, strings.Repeat("a", 64)) {
		t.Errorf("own source leaks the credential or webhook hash: %s", body)
	}
	if !strings.Contains(body, `"set":true`) || !strings.Contains(body, `"hint":"wxyz"`) || !strings.Contains(body, `"editable":true`) {
		t.Errorf("own source: %s", body)
	}
	// Another organization's source (never returned by the service) would
	// still render only the projection.
	raw, _ = json.Marshal(toContentSourceResponse(&own, shared.NewID()))
	if strings.Contains(string(raw), "git.internal.example") {
		t.Errorf("foreign source rendered in full: %s", raw)
	}
}

// SECURITY: a platform snapshot's projection does not name the platform
// administrators who synced, promoted or rejected it; an organization's own
// snapshot does name its members.
func TestContentSnapshotResponse_HidesPlatformAdmins(t *testing.T) {
	admin, member := shared.NewID(), shared.NewID()
	tenant := shared.NewID()
	sn := &cs.Snapshot{ID: shared.NewID(), SourceID: shared.NewID(), Scope: cs.ScopePlatform, SyncedBy: &admin, PromotedBy: &admin, RejectedBy: &admin, State: cs.StatePromoted}
	src := &cs.Source{ID: sn.SourceID, Scope: cs.ScopePlatform}
	for _, in := range []*cs.Source{src, nil} {
		raw, _ := json.Marshal(toContentSnapshotResponse(sn, in, true))
		if strings.Contains(string(raw), admin.String()) {
			t.Fatalf("platform snapshot names a platform administrator: %s", raw)
		}
	}
	own := &cs.Snapshot{ID: shared.NewID(), SourceID: shared.NewID(), Scope: cs.ScopeTenant, TenantID: &tenant, SyncedBy: &member, PromotedBy: &member, State: cs.StatePromoted}
	raw, _ := json.Marshal(toContentSnapshotResponse(own, &cs.Source{ID: own.SourceID, Scope: cs.ScopeTenant, TenantID: &tenant}, false))
	if !strings.Contains(string(raw), member.String()) {
		t.Fatalf("an organization's own snapshot lost its member ids: %s", raw)
	}
}
