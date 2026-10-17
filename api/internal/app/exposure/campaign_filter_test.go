package exposure

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every condition must parse: a dropped condition widens the set a resolve
// changes (an unparseable asset_id next to a severity used to mean every
// finding of that severity in the organization).
func TestParseCampaignFilter_Strict(t *testing.T) {
	asset := shared.NewID().String()
	bad := map[string]map[string]any{
		"unknown key":         {"severity": "high", "owner": "x"},
		"bad asset id":        {"asset_id": "bad", "severity": "critical"},
		"bad severity":        {"severity": "urgent"},
		"bad source":          {"source": "nope"},
		"bad status":          {"status": "open"},
		"bad cve":             {"cve_id": "log4shell"},
		"bad finding id":      {"finding_ids": []any{"x"}},
		"number value":        {"severity": 3},
		"mixed array":         {"severities": []any{"high", 2}},
		"empty string":        {"tool_name": ""},
		"empty list":          {"finding_ids": []any{}},
		"singular and plural": {"severity": "high", "severities": []any{"low"}},
		"two assets":          {"asset_id": []any{asset, asset}},
		"key with other":      {"remediation_key": "upgrade:x", "severity": "high"},
		"empty key":           {"remediation_key": " "},
		"non-string key":      {"remediation_key": 1},
	}
	for name, raw := range bad {
		if err := ValidateCampaignFilter(raw); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}

	good := []map[string]any{
		nil,
		{},
		{"severity": "critical", "asset_id": asset},
		{"severities": []any{"high", "critical"}, "sources": []any{"sast"}},
		{"finding_ids": []any{shared.NewID().String()}},
		{"cve_ids": []any{"CVE-2024-12345"}, "statuses": []any{"new"}},
		{"remediation_key": "upgrade:npm/lodash:4.17.21"},
		{"tool_name": "trivy", "search": "openssl"},
	}
	for _, raw := range good {
		if err := ValidateCampaignFilter(raw); err != nil {
			t.Errorf("%v: %v", raw, err)
		}
	}
}

// A status is not scope: "every new finding" is the whole organization. A
// stored filter that does not parse has no scope either.
func TestFindingFilterHasScope_StatusAloneAndInvalid(t *testing.T) {
	tid := shared.NewID()
	if findingFilterHasScope(campaignFilterToFindingFilter(tid, map[string]any{"statuses": []any{"new"}})) {
		t.Error("a status-only filter counts as scope")
	}
	if findingFilterHasScope(campaignFilterToFindingFilter(tid, map[string]any{"asset_id": "bad", "severity": "critical"})) {
		t.Error("an invalid stored filter counts as scope (a condition was dropped)")
	}
	if !findingFilterHasScope(campaignFilterToFindingFilter(tid, map[string]any{"cve_id": "CVE-2021-44228", "status": "new"})) {
		t.Error("cve + status lost its scope")
	}
}
