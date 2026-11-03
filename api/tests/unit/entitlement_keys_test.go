package unit

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
)

// Every limit and every deniable feature goes through the entitlement
// service with a key from pkg/domain/limits (docs/architecture/limits.md).
// These tests keep it that way: the key registry is listed here and in the
// architecture doc, and no code anywhere else checks a plan, tier or edition
// by name.

// TestLimitKeysAreListed fails when a limit key or named feature is added,
// removed or renamed without updating this list and the architecture doc.
func TestLimitKeysAreListed(t *testing.T) {
	want := []string{
		"seats", "assets", "sensors", "api_keys", "ci_trusts", "invites_per_day",
		"platform_scans_per_day", "platform_scans_concurrent", "findings", "lifecycle_sub_statuses", "lifecycle_schemes",
		"storage_mb", "orgs_per_user", "dashboard_refresh_floor_minutes",
		"content_sources", "content_storage_mb", "content_sync_floor_minutes", "content_snapshot_max_mb",
	}
	got := make([]string, 0, len(limits.Keys))
	for _, k := range limits.Keys {
		got = append(got, string(k))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("limit keys changed:\n got %v\nwant %v\nupdate this list and docs/architecture/limits.md", got, want)
	}
	wantNamed := []string{"content_sources.private_git", "content_sources.review_policy", "content_sources.webhook", "ldap", "scim", "sso.connections", "sso.enforcement", "sso.group_links"}
	if strings.Join(limits.NamedFeatures, ",") != strings.Join(wantNamed, ",") {
		t.Fatalf("named features changed: %v; update this list and docs/architecture/limits.md", limits.NamedFeatures)
	}

	doc, err := os.ReadFile("../../docs/architecture/limits.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range append(want, wantNamed...) {
		if !strings.Contains(string(doc), "`"+k+"`") {
			t.Errorf("docs/architecture/limits.md does not list `%s`", k)
		}
	}
	for _, f := range limits.Features() {
		if !limits.IsFeature(f) {
			t.Errorf("Features() lists %q but IsFeature refuses it", f)
		}
	}
}

// adHocEntitlement matches a check of a commercial plan, tier or edition by
// name: comparisons with plan names, plan-named helpers, and the removed plan
// tables. Words such as "plan" and "tier" alone are not matched: scan plans
// and scope tiers are product concepts.
var adHocEntitlement = regexp.MustCompile(`(==|!=)\s*["'](free|pro|enterprise|premium|paid)["']` +
	`|["'](free|pro|enterprise|premium|paid)["']\s*(===?|!==?)` +
	`|case\s+["'](free|pro|enterprise|premium|paid)["']` +
	`|\bIs(Enterprise|Pro|Free|Paid|Premium)(Plan|Tier|Edition|Org|Tenant)?\b` +
	`|\b(Plan|Tier|Edition)(Free|Pro|Enterprise|Paid|Premium)\b` +
	`|\btenant_plans\b|\bplan_limits\b|\bplan_modules\b` +
	`|\.plan\s*(===?|!==?)\s*["']`)

// TestNoAdHocPlanChecks fails on a plan, tier or edition check outside the
// entitlement service, in the API and the web console.
func TestNoAdHocPlanChecks(t *testing.T) {
	roots := []struct {
		dir  string
		exts []string
	}{
		{"../../internal", []string{".go"}},
		{"../../pkg", []string{".go"}},
		{"../../cmd", []string{".go"}},
		{"../../../web/src", []string{".ts", ".tsx"}},
	}
	scanned := 0
	for _, root := range roots {
		if _, err := os.Stat(root.dir); err != nil {
			if root.dir == "../../../web/src" {
				continue // the API checked out alone
			}
			t.Fatal(err)
		}
		err := filepath.WalkDir(root.dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "dictionaries" {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if strings.HasSuffix(name, "_test.go") || strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") {
				return nil
			}
			ok := false
			for _, e := range root.exts {
				ok = ok || strings.HasSuffix(name, e)
			}
			if !ok {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			for i, line := range strings.Split(string(raw), "\n") {
				if adHocEntitlement.MatchString(line) {
					t.Errorf("%s:%d: ad-hoc plan/tier check; use the entitlement service with a key from pkg/domain/limits: %s",
						path, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files: wrong working directory?", scanned)
	}
}

// The guard itself: it catches the shapes it is meant to catch.
func TestAdHocEntitlementPattern(t *testing.T) {
	for _, bad := range []string{
		`if t.Plan() == "enterprise" {`, `if plan != "free" {`, `case "pro":`, `if IsEnterprisePlan(t) {`,
		`p := PlanFree`, `SELECT plan FROM tenant_plans`, `if (tenant.plan === 'Enterprise') {`, `{org.plan === "pro" && <Badge/>}`,
	} {
		if !adHocEntitlement.MatchString(bad) {
			t.Errorf("not caught: %s", bad)
		}
	}
	for _, good := range []string{
		`if plan == nil {`, `if tier == dom.TierT0 {`, `if st.Tier == stage.TierPassive {`, `v.Edition = ""`, `free := len(slots)`,
	} {
		if adHocEntitlement.MatchString(good) {
			t.Errorf("false positive: %s", good)
		}
	}
}

// planWording matches commercial plan, edition and upgrade wording. The core
// talks of limits and of what is "not available for this organization";
// plans and prices exist only in a hosted service's own control plane.
var planWording = regexp.MustCompile(`(?i)\b(your|organization'?s|this organization'?s|their|the organization's) plan\b` +
	`|\bupgrade (your|to) (plan|pro|enterprise)\b|\bOSS edition\b|\bfree plan\b|\b(pro|enterprise) (plan|tier|edition)\b` +
	`|plan ?& ?usage|\benterprise only\b|\benterprise edition\b`)

// TestNoPlanWording fails on plan or edition wording in the API code and the
// web console, including its translations.
func TestNoPlanWording(t *testing.T) {
	roots := []struct {
		dir  string
		exts []string
	}{
		{"../../internal", []string{".go"}},
		{"../../pkg", []string{".go"}},
		{"../../cmd", []string{".go"}},
		{"../../../web/src", []string{".ts", ".tsx", ".json"}},
	}
	for _, root := range roots {
		if _, err := os.Stat(root.dir); err != nil {
			if root.dir == "../../../web/src" {
				continue
			}
			t.Fatal(err)
		}
		err := filepath.WalkDir(root.dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "generated" {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if strings.HasSuffix(name, "_test.go") || strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") {
				return nil
			}
			ok := false
			for _, e := range root.exts {
				ok = ok || strings.HasSuffix(name, e)
			}
			if !ok {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(raw), "\n") {
				if planWording.MatchString(line) {
					t.Errorf("%s:%d: plan or edition wording; say what applies (limits, not available for this organization): %s",
						path, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestEntitlementKeysAreRegisteredAndDescribed keeps one registry: every limit
// key, named feature and module feature has a description, and the
// description tables hold no key that is not registered.
func TestEntitlementKeysAreRegisteredAndDescribed(t *testing.T) {
	seen := map[limits.Key]bool{}
	for _, k := range limits.Keys {
		seen[k] = true
		if strings.TrimSpace(limits.KeyDescriptions[k]) == "" {
			t.Errorf("limit key %q has no description in limits.KeyDescriptions", k)
		}
	}
	for k := range limits.KeyDescriptions {
		if !seen[k] {
			t.Errorf("limits.KeyDescriptions describes %q, which is not in limits.Keys", k)
		}
	}
	named := map[string]bool{}
	for _, f := range limits.NamedFeatures {
		named[f] = true
		if strings.TrimSpace(limits.NamedFeatureDescriptions[f]) == "" {
			t.Errorf("named feature %q has no description in limits.NamedFeatureDescriptions", f)
		}
	}
	for f := range limits.NamedFeatureDescriptions {
		if !named[f] {
			t.Errorf("limits.NamedFeatureDescriptions describes %q, which is not in limits.NamedFeatures", f)
		}
	}
	for _, f := range limits.Features() {
		if named[f] {
			continue
		}
		d, ok := moduledom.Lookup(f)
		if !ok || strings.TrimSpace(d.Description) == "" {
			t.Errorf("module feature %q has no description in the module registry", f)
		}
	}
}

// TestUnknownEntitlementKeysFail: a key or feature outside the registry is
// refused everywhere a key is accepted.
func TestUnknownEntitlementKeysFail(t *testing.T) {
	for _, bad := range []string{"", "unknown_key", "SEATS", "seats "} {
		if limits.Key(bad).IsValid() {
			t.Errorf("limit key %q accepted", bad)
		}
		if limits.IsFeature(bad) {
			t.Errorf("feature %q accepted", bad)
		}
		if err := (limits.Limits{limits.Key(bad): 1}).Validate(); err == nil {
			t.Errorf("Limits.Validate accepted key %q", bad)
		}
	}
	if _, err := limits.DecodeLimits([]byte(`{"unknown_key": 5}`)); err == nil {
		t.Error("DecodeLimits accepted an unknown key")
	}
}

// literalKey matches a limit key built from a string literal, which would
// skip the registry (use the constants of pkg/domain/limits).
var literalKey = regexp.MustCompile(`\blimits\.Key\(\s*"`)

// TestNoLiteralLimitKeys fails when code outside the limits package makes a
// limit key from a string literal.
func TestNoLiteralLimitKeys(t *testing.T) {
	for _, dir := range []string{"../../internal", "../../pkg", "../../cmd"} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(raw), "\n") {
				if literalKey.MatchString(line) {
					t.Errorf("%s:%d: limit key from a string literal; use a constant registered in pkg/domain/limits", path, i+1)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !literalKey.MatchString(`k := limits.Key("seats")`) {
		t.Error("literalKey no longer matches the shape it guards")
	}
}
