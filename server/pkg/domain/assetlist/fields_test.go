package assetlist

import (
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// Every legacy param of GET /assets is either a field or an alias, so old
// links keep working.
func TestLegacyParamsResolve(t *testing.T) {
	legacy := map[string]string{
		"types": "domain", "lenses": "external_surface", "criticalities": "high", "statuses": "active",
		"scopes": "internal", "exposures": "public", "tags": "a,b", "exclude_tags": "c", "search": "api",
		"min_risk_score": "10", "max_risk_score": "90", "has_findings": "true", "coverage": "covered",
		"coverage_cause": "no_sensor", "freshness": "stale", "resolution": "resolving", "technology": "nginx",
		"technology_version": "1.2", "technology_category": "web_server", "is_crown_jewel": "true", "sub_type": "x",
		"business_unit_ids": "00000000-0000-0000-0000-000000000001", "asset_group_ids": "00000000-0000-0000-0000-000000000001",
		"owner_ids": "00000000-0000-0000-0000-000000000001", "ids": "00000000-0000-0000-0000-000000000001",
		"under": "example.com", "in_cidr": "10.0.0.0/8", "has_owner": "false", "data_classifications": "public",
		"is_control_plane": "true", "internet_facing": "true", "environments": "production", "providers": "unset",
		"last_seen_after": "2026-01-01", "last_seen_before": "2026-01-02", "expires_after": "2026-01-01",
		"expires_before": "2026-01-02", "attribution": "approved", "covered_by": "00000000-0000-0000-0000-000000000001",
		"scope_status": "in_scope", "monitoring_state": "monitored", "liveness": "alive", "primary": "true",
		"discovered_by": "tenant_scanned", "discovery_technique": "cert_transparency", "min_confidence": "10",
		"max_confidence": "90", "first_seen_after": "2026-01-01", "first_seen_before": "2026-01-02", "program_assets": "only",
	}
	for k, v := range legacy {
		q := url.Values{k: {v}}
		if _, err := filterspec.ParseValues(q, Fields, filterspec.Options{Unknown: filterspec.UnknownStrict}); err != nil {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
}

// Every template that reads another table names the tenant or the asset's
// own row, and no template is built from input.
func TestTemplatesPinTenant(t *testing.T) {
	for _, f := range Fields.Fields() {
		tpls := []string{f.SQL, f.BoolTemplate}
		for _, x := range f.Templates {
			tpls = append(tpls, x)
		}
		for _, x := range f.EnumTemplates {
			tpls = append(tpls, x)
		}
		for _, tpl := range tpls {
			if strings.Contains(strings.ReplaceAll(tpl, "FROM unnest", ""), "FROM ") && !strings.Contains(tpl, "{tenant}") && !strings.Contains(tpl, "a.tenant_id") {
				t.Errorf("field %s reads another table without a tenant pin", f.Name)
			}
		}
	}
}

func TestBothVariantsCompile(t *testing.T) {
	if FieldsFor(true) == FieldsFor(false) {
		t.Fatal("variants must differ")
	}
	a, _ := FieldsFor(true).Field("monitoring_state")
	b, _ := FieldsFor(false).Field("monitoring_state")
	if a.SQL == b.SQL {
		t.Fatal("the monitoring state input is not in the SQL")
	}
}

// Every attribution word the web inventory sends parses, alone and as the
// Needs attention queues send them (C21: provider_address was refused with
// "1 filter error", so the decide-monitoring and validate-primary queues and
// the inventory's provider addresses chip never loaded).
func TestAttributionValuesParse(t *testing.T) {
	cases := []struct {
		name   string
		params url.Values
	}{
		{"provider_address alone", url.Values{"attribution": {"provider_address"}}},
		{"all", url.Values{"attribution": {"all"}}},
		{"every inventory value", url.Values{"attribution": {"confirmed,discovered,unknown,needs_review,candidate,dependency,monitor_only,rejected,provider_address"}}},
		{"decide monitoring queue", url.Values{"monitoring_state": {"pending_decision,unvalidated"}, "attribution": {"all"}}},
		{"validate primary queue", url.Values{"monitoring_state": {"pending_decision,unvalidated"}, "attribution": {"all"}, "primary": {"true"}}},
		{"not provider_address", url.Values{"attribution_not": {"provider_address"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := filterspec.ParseValues(c.params, Fields, filterspec.Options{Unknown: filterspec.UnknownStrict}); err != nil {
				t.Fatalf("%v: %v", c.params, err)
			}
		})
	}
}

// A provider's shared address is its own attribution value: approved and
// attributed leave it out, dependency and all keep it (attribution.ParseFilter).
func TestAttributionExpandProviderAddress(t *testing.T) {
	exp := attributionExpand()
	has := func(word, v string) bool {
		for _, x := range exp[word] {
			if x == v {
				return true
			}
		}
		return false
	}
	for word, want := range map[string]bool{"approved": false, "attributed": false, "dependency": true, "all": true} {
		if got := has(word, "provider_address"); got != want {
			t.Errorf("%s includes provider_address = %v, want %v", word, got, want)
		}
	}
	if !strings.Contains(attributionStateSQL, "provider_shared_front_end") || !strings.Contains(attributionStateSQL, "'provider_address'") {
		t.Errorf("the attribution state does not name the provider address: %s", attributionStateSQL)
	}
}
