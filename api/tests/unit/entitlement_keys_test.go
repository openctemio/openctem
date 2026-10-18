package unit

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
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
	}
	got := make([]string, 0, len(limits.Keys))
	for _, k := range limits.Keys {
		got = append(got, string(k))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("limit keys changed:\n got %v\nwant %v\nupdate this list and docs/architecture/limits.md", got, want)
	}
	wantNamed := []string{}
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
