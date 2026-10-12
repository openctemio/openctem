package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fixedAdmins lists the same administrators for one tenant, none for others.
type fixedAdmins struct {
	tenant shared.ID
	ids    []shared.ID
}

func (f fixedAdmins) ActiveAdminIDs(_ context.Context, tenantID shared.ID) ([]shared.ID, error) {
	if tenantID != f.tenant {
		return nil, nil
	}
	return f.ids, nil
}

type inAppCapture struct {
	sent []notificationdom.NotificationParams
}

func (c *inAppCapture) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	c.sent = append(c.sent, p)
	return nil
}

// TestCISecurityAlerts: every administrator hears of a break-glass when it
// is created and each time it lets a failing run pass; a burst of refused
// token exchanges raises one alert per tenant while it lasts.
func TestCISecurityAlerts(t *testing.T) {
	inApp := &inAppCapture{}
	ob := &ciAlertCapture{}
	admins := fixedAdmins{ids: []shared.ID{shared.NewID(), shared.NewID()}}
	var lister *fixedAdmins
	r := newCIRigWith(t, cirunapp.Config{WebBaseURL: "https://console.example"}, func(d *cirunapp.Deps) {
		lister = &admins
		d.Alerts = cirunapp.NewAdminAlerts(lister, inApp, ob, logger.NewNop())
	})
	admins.tenant = r.tenant
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	const sha = "3333333333333333333333333333333333333333"
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"

	// A committed secret fails the run.
	code, ex := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	token, runID := ex["token"].(string), ex["run_id"].(string)
	secret := ciFinding("AWS key", "aws-access-key", "high", ctis.FindingTypeSecret, "config.go", 3)
	if resp, out := r.post("/api/v1/ci/runs/"+runID+"/results", token, ciReport(repoName, secret)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", resp.StatusCode, out)
	}
	assetID, _ := shared.IDFromString(ex["repository_asset_id"].(string))

	// Created: both administrators in-app, and the channel event.
	if _, err := r.svc.CreateOverride(ctx, r.tenant, cirunapp.OverrideInput{RepositoryAssetID: assetID,
		CommitSHA: sha[:12], Reason: "release blocked by a known false positive"}, cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatal(err)
	}
	if len(inApp.sent) != 2 || ob.count("ci.break_glass") != 1 {
		t.Fatalf("break-glass created: %d in-app, %d channel", len(inApp.sent), ob.count("ci.break_glass"))
	}
	for i, n := range inApp.sent {
		if n.TenantID != r.tenant || n.AudienceID == nil || *n.AudienceID != admins.ids[i] ||
			n.NotificationType != notificationdom.TypeCISecurity || !strings.Contains(n.Body, "release blocked") {
			t.Fatalf("in-app notice %d: %+v", i, n)
		}
	}
	// Used: each use is announced again.
	if _, v := r.post("/api/v1/ci/runs/"+runID+"/evaluate", token, nil); v["verdict"] != "pass" || v["override"] == nil {
		t.Fatalf("override: %v", v)
	}
	if len(inApp.sent) != 4 || ob.count("ci.break_glass") != 2 || !strings.Contains(inApp.sent[3].Title, "used") {
		t.Fatalf("break-glass used: %d in-app, %d channel", len(inApp.sent), ob.count("ci.break_glass"))
	}
	for _, p := range ob.sent {
		if p.TenantID != r.tenant {
			t.Fatalf("an alert for another tenant: %+v", p)
		}
	}

	// A burst of refused exchanges: one alert while it lasts.
	job := cirunapp.NewAlertJob(r.repo, ob, nil, cirun.StatusPolicy{}, logger.NewNop())
	for i := 0; i < cirun.TokenRefusalBurst-1; i++ {
		if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "evil/api", "main", sha, nil)); code != http.StatusUnauthorized {
			t.Fatalf("refusal %d: %d", i, code)
		}
	}
	if _, err := job.ReconcileTenant(ctx, r.tenant); err != nil || ob.count("ci.token_refusals") != 0 {
		t.Fatalf("below the burst: %d %v", ob.count("ci.token_refusals"), err)
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "evil/api", "main", sha, nil)); code != http.StatusUnauthorized {
		t.Fatalf("refusal: %d", code)
	}
	for range 2 {
		if _, err := job.ReconcileTenant(ctx, r.tenant); err != nil {
			t.Fatal(err)
		}
	}
	if ob.count("ci.token_refusals") != 1 {
		t.Fatalf("burst alerts: %d, want one", ob.count("ci.token_refusals"))
	}
	// The other tenant, with no refusals, raises nothing.
	if _, err := job.ReconcileTenant(ctx, r.other); err != nil || ob.count("ci.token_refusals") != 1 {
		t.Fatalf("other tenant: %d %v", ob.count("ci.token_refusals"), err)
	}
	// Tenants with only a trust configuration are walked too.
	tenants, err := r.repo.PipelineTenantsForPlatform(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range tenants {
		found = found || id == r.tenant
	}
	if !found {
		t.Fatal("the alert job does not walk the tenant")
	}
}
