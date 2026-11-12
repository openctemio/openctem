package routes

// GET /api/v1/me/dashboards/home: the lists, the landing rule and the figures
// of the landing dashboard in one read, identical to what the per-dashboard
// routes return for the same caller.

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type homeResp struct {
	Personal     []struct{ ID string }  `json:"personal"`
	Organization *[]struct{ ID string } `json:"organization"`
	Landing      *struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"landing"`
	Data *dataResp `json:"data"`
}

func (e *widgetEnv) home(t *testing.T, user shared.ID, admin bool, perms []string, choice string) (homeResp, string) {
	t.Helper()
	path := "/api/v1/me/dashboards/home"
	if choice != "" {
		path += "?choice=" + choice
	}
	code, body := e.call(user, admin, perms, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, code, body)
	}
	var out homeResp
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out, body
}

func TestDashboardHome_OneReadLandingAndScope_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	layout := []any{metricWidget("w_open", "findings.open", nil)}
	mine := e.createPersonal(t, h.memberA, false, layout)
	theirs := e.createPersonal(t, h.memberFull, false, layout)

	code, body := e.call(h.owner, true, nil, http.MethodPost, "/api/v1/organization/dashboards", map[string]any{"name": "Org", "layout": layout})
	if code != http.StatusCreated {
		t.Fatalf("create org = %d %s", code, body)
	}
	var org struct{ ID string }
	_ = json.Unmarshal([]byte(body), &org)
	view := []string{permission.DashboardsOrgView.String()}

	// Without the organization permission: no organization list at all, and
	// the landing is the person's own dashboard with its figures.
	out, raw := e.home(t, h.memberA, false, nil, "")
	if out.Organization != nil {
		t.Errorf("organization list present without dashboards:org:view: %s", raw)
	}
	if len(out.Personal) != 1 || out.Personal[0].ID != mine || out.Landing == nil || out.Landing.Kind != "personal" || out.Landing.ID != mine {
		t.Fatalf("home = %s", raw)
	}
	if out.Data == nil || openValue(t, *out.Data) != e.data(t, h.memberA, false, nil, "/api/v1/me/dashboards/"+mine+"/data").Widgets[0].Scalar.Value {
		t.Errorf("home figures differ from the data route: %s", raw)
	}
	// An organization choice, a foreign personal dashboard and garbage are
	// all ignored silently: same answer as no choice.
	for _, choice := range []string{"organization:" + org.ID, "personal:" + theirs, "personal:" + shared.NewID().String(), "x", "organization:"} {
		got, _ := e.home(t, h.memberA, false, nil, choice)
		if got.Landing == nil || got.Landing.ID != mine || got.Organization != nil {
			t.Errorf("choice %q: landing %+v", choice, got.Landing)
		}
	}

	// With organization view: the list is there; with no personal default
	// the organization dashboard lands, and a remembered personal choice wins.
	out, raw = e.home(t, h.memberA, false, view, "")
	if out.Organization == nil || len(*out.Organization) != 1 || (*out.Organization)[0].ID != org.ID {
		t.Fatalf("organization list = %s", raw)
	}
	if out.Landing == nil || out.Landing.Kind != "organization" || out.Landing.ID != org.ID || out.Data == nil {
		t.Errorf("landing = %+v data=%v", out.Landing, out.Data != nil)
	}
	orgData := e.data(t, h.memberA, false, view, "/api/v1/organization/dashboards/"+org.ID+"/data")
	if !reflect.DeepEqual(out.Data.Scope, orgData.Scope) || openValue(t, *out.Data) != openValue(t, orgData) {
		t.Errorf("organization figures differ from the data route")
	}
	if got, _ := e.home(t, h.memberA, false, view, "personal:"+mine); got.Landing.Kind != "personal" || got.Landing.ID != mine {
		t.Errorf("remembered personal choice = %+v", got.Landing)
	}
	// A personal default beats the organization default.
	if code, b := e.call(h.memberA, false, nil, http.MethodPost, "/api/v1/me/dashboards/"+mine+"/default", nil); code >= 300 {
		t.Fatalf("set default = %d %s", code, b)
	}
	if got, _ := e.home(t, h.memberA, false, view, ""); got.Landing.Kind != "personal" || got.Landing.ID != mine {
		t.Errorf("personal default lost to organization: %+v", got.Landing)
	}

	// Another person never sees this person's dashboards in the home.
	if got, _ := e.home(t, h.memberFull, false, nil, "personal:"+mine); got.Landing == nil || got.Landing.ID != theirs {
		t.Errorf("foreign choice leaked: %+v", got.Landing)
	}

	// Without dashboard:read the lists still come, the figures do not.
	noRead := []string{permission.AssetsRead.String()}
	if got, raw := e.home(t, h.memberA, false, noRead, ""); got.Data != nil || got.Landing == nil {
		t.Errorf("without dashboards:read: %s", raw)
	}

	// A person with nothing: empty list, no landing, no figures.
	if got, raw := e.home(t, h.owner, false, nil, ""); got.Landing != nil || got.Data != nil || len(got.Personal) != 0 {
		t.Errorf("empty home = %s", raw)
	}
}
