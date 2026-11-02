package technology

import (
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// Every compiled filter starts with the tenant, adds the data scope for a
// restricted caller on the asset each row belongs to, filters in the row
// stage and sorts in the group stage.
func TestFieldsCompile(t *testing.T) {
	tenant := shared.NewID()
	spec, err := filterspec.ParseValues(url.Values{
		"version_known": {"false"}, "category": {"web_server"}, "has_cves": {"true"}, "sort": {"-cve_count,name"},
	}, Fields, filterspec.Options{Unknown: filterspec.UnknownStrict})
	if err != nil {
		t.Fatal(err)
	}
	user := shared.NewID()
	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenant, UserID: user,
		Scope: &shared.DataScope{TenantID: tenant, UserID: user}})
	if err != nil {
		t.Fatal(err)
	}
	w, err := filterspec.Compile(spec, Fields, actor)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(w.SQL, "t.tenant_id = $1") || !strings.Contains(w.SQL, "t.asset_id") {
		t.Errorf("WHERE = %s", w.SQL)
	}
	if !strings.Contains(w.SQL, "t.version <> ''") || !strings.Contains(w.SQL, "software_version_vulns") {
		t.Errorf("row filters missing: %s", w.SQL)
	}
	if w.OrderBy != "c.cve_count DESC, g.name_key ASC, g.name_key, g.version" {
		t.Errorf("ORDER BY = %s", w.OrderBy)
	}
	// Sort-only keys are not filters.
	if _, err := filterspec.ParseValues(url.Values{"asset_count": {"2"}}, Fields,
		filterspec.Options{Unknown: filterspec.UnknownStrict}); err == nil {
		t.Error("asset_count accepted as a filter")
	}
}
