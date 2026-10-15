package exposure

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A campaign's finding_filter decides which findings a resolve changes, so it
// is parsed strictly: an unknown key, a value of the wrong type or a value
// that does not parse is an error, never dropped. Dropping one condition
// widens the set (`{"asset_id":"bad","severity":"critical"}` would otherwise
// mean every critical finding of the organization).

// ErrInvalidCampaignFilter refuses a finding_filter that does not parse.
var ErrInvalidCampaignFilter = fmt.Errorf("%w: invalid finding_filter", shared.ErrValidation)

const (
	maxCampaignFilterValues = 2000 // finding_ids of a large task; the resolve cap
	maxCampaignFilterText   = 255
)

// campaignFilterAliases maps every accepted key to its canonical name.
var campaignFilterAliases = map[string]string{
	"severities": "severities", "severity": "severities",
	"sources": "sources", "source": "sources",
	"statuses": "statuses", "status": "statuses",
	"cve_ids": "cve_ids", "cve_id": "cve_ids",
	"finding_ids": "finding_ids", "finding_id": "finding_ids",
	"asset_id":        "asset_id",
	"tool_name":       "tool_name",
	"search":          "search",
	"remediation_key": "remediation_key",
}

var campaignCVEPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func filterError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidCampaignFilter, fmt.Sprintf(format, args...))
}

// ValidateCampaignFilter checks a finding_filter before it is stored.
func ValidateCampaignFilter(raw map[string]any) error {
	_, err := parseCampaignFilter(shared.NewID(), raw)
	return err
}

// parseCampaignFilter maps a finding_filter onto a FindingFilter with the
// tenant pinned. Every key must be known, appear once (singular or plural
// form), and every value must parse. A remediation_key campaign takes no
// other condition: it is resolved and counted through its fix only.
func parseCampaignFilter(tenantID shared.ID, raw map[string]any) (vulnerability.FindingFilter, error) {
	f := vulnerability.NewFindingFilter().WithTenantID(tenantID)
	seen := make(map[string]string, len(raw))
	for k := range raw {
		canon, ok := campaignFilterAliases[k]
		if !ok {
			return f, filterError("unknown key %q", k)
		}
		if other, dup := seen[canon]; dup {
			return f, filterError("%q and %q name the same condition", other, k)
		}
		seen[canon] = k
	}
	if key, ok := seen["remediation_key"]; ok {
		if len(seen) > 1 {
			return f, filterError("remediation_key cannot be combined with other conditions")
		}
		s, ok := raw[key].(string)
		if !ok || strings.TrimSpace(s) == "" || len(s) > maxCampaignFilterText {
			return f, filterError("remediation_key must be a non-empty string")
		}
		return f, nil
	}

	for canon, key := range seen {
		values, err := strictStrings(raw[key], key)
		if err != nil {
			return f, err
		}
		if err := applyCampaignCondition(&f, canon, key, values); err != nil {
			return f, err
		}
	}
	return f, nil
}

func applyCampaignCondition(f *vulnerability.FindingFilter, canon, key string, values []string) error {
	single := func() (string, error) {
		if len(values) != 1 {
			return "", filterError("%s takes one value", key)
		}
		if len(values[0]) > maxCampaignFilterText {
			return "", filterError("%s is too long", key)
		}
		return values[0], nil
	}
	switch canon {
	case "severities":
		for _, v := range values {
			sev, err := vulnerability.ParseSeverity(v)
			if err != nil {
				return filterError("unknown severity %q", v)
			}
			f.Severities = append(f.Severities, sev)
		}
	case "sources":
		for _, v := range values {
			src, err := vulnerability.ParseFindingSource(v)
			if err != nil {
				return filterError("unknown source %q", v)
			}
			f.Sources = append(f.Sources, src)
		}
	case "statuses":
		for _, v := range values {
			st := vulnerability.FindingStatus(v)
			if !st.IsValid() {
				return filterError("unknown status %q", v)
			}
			f.Statuses = append(f.Statuses, st)
		}
	case "cve_ids":
		for _, v := range values {
			if !campaignCVEPattern.MatchString(v) {
				return filterError("invalid CVE id %q", v)
			}
		}
		f.CVEIDs = values
	case "finding_ids":
		for _, v := range values {
			if _, err := shared.IDFromString(v); err != nil {
				return filterError("invalid finding id %q", v)
			}
		}
		f.FindingIDs = values
	case "asset_id":
		v, err := single()
		if err != nil {
			return err
		}
		id, err := shared.IDFromString(v)
		if err != nil {
			return filterError("invalid asset_id %q", v)
		}
		f.AssetID = &id
	case "tool_name":
		v, err := single()
		if err != nil {
			return err
		}
		f.ToolName = &v
	case "search":
		v, err := single()
		if err != nil {
			return err
		}
		f.Search = &v
	}
	return nil
}

// strictStrings reads a value that must be a non-empty string or a non-empty
// array of non-empty strings.
func strictStrings(v any, key string) ([]string, error) {
	switch val := v.(type) {
	case string:
		if strings.TrimSpace(val) == "" {
			return nil, filterError("%s is empty", key)
		}
		return []string{val}, nil
	case []string:
		return checkStrings(val, key)
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			s, ok := item.(string)
			if !ok {
				return nil, filterError("%s must hold strings", key)
			}
			out = append(out, s)
		}
		return checkStrings(out, key)
	default:
		return nil, filterError("%s must be a string or a list of strings", key)
	}
}

func checkStrings(vals []string, key string) ([]string, error) {
	if len(vals) == 0 {
		return nil, filterError("%s is empty", key)
	}
	if len(vals) > maxCampaignFilterValues {
		return nil, filterError("%s has more than %d values", key, maxCampaignFilterValues)
	}
	for _, s := range vals {
		if strings.TrimSpace(s) == "" {
			return nil, filterError("%s holds an empty value", key)
		}
	}
	return vals, nil
}
