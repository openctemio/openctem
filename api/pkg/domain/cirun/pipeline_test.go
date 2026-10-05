package cirun

import (
	"strings"
	"testing"
	"time"
)

func TestWorkflowPath(t *testing.T) {
	cases := []struct {
		name     string
		provider Provider
		repo     string
		claim    string
		want     string
	}{
		{"github", ProviderGitHub, "acme/api", "acme/api/.github/workflows/scan.yml@refs/heads/main", ".github/workflows/scan.yml"},
		{"github case differs", ProviderGitHub, "acme/api", "Acme/API/.github/workflows/scan.yml@refs/pull/7/merge", ".github/workflows/scan.yml"},
		{"github renamed repo still finds the path", ProviderGitHub, "acme/new-name", "acme/old-name/.github/workflows/scan.yml@refs/heads/main", ".github/workflows/scan.yml"},
		{"github branch with @", ProviderGitHub, "acme/api", "acme/api/.github/workflows/scan.yml@refs/heads/feat@x", ".github/workflows/scan.yml"},
		{"github traversal refused", ProviderGitHub, "acme/api", "acme/api/../../etc/passwd@refs/heads/main", ""},
		{"github empty", ProviderGitHub, "acme/api", "", ""},
		{"gitlab", ProviderGitLab, "grp/proj", "gitlab.example.com/grp/proj//.gitlab-ci.yml@refs/heads/main", ".gitlab-ci.yml"},
		{"gitlab nested", ProviderGitLab, "grp/proj", "gitlab.example.com/grp/proj//ci/security.yml@refs/heads/main", "ci/security.yml"},
		{"gitlab no claim", ProviderGitLab, "grp/proj", "", GitLabDefaultConfigPath},
		{"control characters refused", ProviderGitLab, "grp/proj", "h/grp/proj//a\x00b.yml@x", ""},
		{"too long refused", ProviderGitLab, "grp/proj", "h/g/p//" + strings.Repeat("a", 600), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := WorkflowPath(c.provider, c.repo, c.claim); got != c.want {
				t.Fatalf("WorkflowPath = %q, want %q", got, c.want)
			}
		})
	}
}

func TestPipelineKeyFromClaims(t *testing.T) {
	base := ParseGitHubClaims(map[string]any{
		"iss": GitHubIssuer, "repository": "acme/api", "repository_id": "123456", "ref": "refs/heads/main",
		"sha": "abc", "jti": "j", "workflow_ref": "acme/api/.github/workflows/scan.yml@refs/heads/main",
	})
	k, r := PipelineKeyFromClaims(ProviderGitHub, GitHubIssuer, base)
	if r != nil || k.ExternalRepoID != "123456" || k.WorkflowPath != ".github/workflows/scan.yml" {
		t.Fatalf("key = %+v, %v", k, r)
	}

	// Renamed repository, another branch: the same key.
	renamed := base
	renamed.Repository = "acme/api-v2"
	renamed.Workflow = "acme/api-v2/.github/workflows/scan.yml@refs/heads/feature/x"
	renamed.Branch, renamed.Ref = "feature/x", "refs/heads/feature/x"
	if k2, r := PipelineKeyFromClaims(ProviderGitHub, GitHubIssuer, renamed); r != nil || k2 != k {
		t.Fatalf("renamed/branch key = %+v, want %+v (%v)", k2, k, r)
	}

	// No repository id (claim missing or not numeric): refused, never keyed
	// by the mutable name.
	for _, id := range []string{"", "acme/api", "12a", strings.Repeat("9", 65)} {
		c := base
		c.RepositoryID = id
		if _, r := PipelineKeyFromClaims(ProviderGitHub, GitHubIssuer, c); r == nil || r.Code != RefusePipelineIdentity {
			t.Fatalf("repository id %q admitted: %v", id, r)
		}
	}
	// No workflow path on GitHub: refused.
	c := base
	c.Workflow = ""
	if _, r := PipelineKeyFromClaims(ProviderGitHub, GitHubIssuer, c); r == nil {
		t.Fatal("GitHub token without workflow_ref admitted")
	}
}

func TestParseGitLabClaims_NoEmail(t *testing.T) {
	c := ParseGitLabClaims(map[string]any{"project_path": "grp/proj", "project_id": 42.0, "user_login": "dev",
		"user_email": "dev@example.com", "ci_config_sha": "ABCDEF"})
	if c.RepositoryID != "42" || c.Actor != "dev" || c.JobWorkflowSHA != "abcdef" {
		t.Fatalf("claims = %+v", c)
	}
	if strings.Contains(strings.ToLower(strings.Join([]string{c.Actor, c.Subject, c.WorkflowName, c.Environment}, " ")), "example.com") {
		t.Fatal("user_email leaked into the claims")
	}
}

func TestTemplate(t *testing.T) {
	gh := Claims{Repository: "acme/api", Workflow: "acme/api/.github/workflows/ci.yml@refs/heads/main",
		JobWorkflowRef: "acme/security/.github/workflows/scan.yml@refs/tags/v2", JobWorkflowSHA: "ABC123"}
	if ref, sha := Template(ProviderGitHub, GitHubIssuer, gh); ref != gh.JobWorkflowRef || sha != "abc123" {
		t.Fatalf("github template = %q %q", ref, sha)
	}
	own := gh
	own.JobWorkflowRef = "acme/api/.github/workflows/ci.yml@refs/heads/main"
	if ref, _ := Template(ProviderGitHub, GitHubIssuer, own); ref != "" {
		t.Fatalf("own workflow reported as template %q", ref)
	}
	gl := Claims{Repository: "grp/proj", Workflow: "gitlab.example.com/grp/proj//.gitlab-ci.yml@refs/heads/main"}
	if ref, _ := Template(ProviderGitLab, "https://gitlab.example.com", gl); ref != "" {
		t.Fatalf("own gitlab config reported as template %q", ref)
	}
	gl.Workflow = "gitlab.example.com/sec/templates//scan.yml@refs/tags/v3"
	if ref, _ := Template(ProviderGitLab, "https://gitlab.example.com", gl); ref != gl.Workflow {
		t.Fatalf("external gitlab config = %q", ref)
	}
	if TemplatePath(gl.Workflow) != "gitlab.example.com/sec/templates//scan.yml" || TemplateVersion(gl.Workflow) != "refs/tags/v3" {
		t.Fatal("template path/version split")
	}
}

func TestSanitizeLabelsAndTools(t *testing.T) {
	if got := SanitizeLabel("  scan\x1b[31m‮  job\n", 100); got != "scan[31m job" {
		t.Fatalf("SanitizeLabel = %q", got)
	}
	if got := SanitizeLabel(strings.Repeat("é", 10), 5); got != "éé" {
		t.Fatalf("rune-safe cap = %q", got)
	}
	in := []ToolLabel{{Name: "Semgrep", Version: "1.2"}, {Name: "<script>", Version: "x"}, {Name: "semgrep", Version: "v1.3.0"}}
	for i := 0; i < 50; i++ {
		in = append(in, ToolLabel{Name: "tool" + strings.Repeat("x", i)})
	}
	out := SanitizeTools(in)
	if len(out) != MaxToolsPerRun {
		t.Fatalf("tools not capped: %d", len(out))
	}
	found := false
	for _, tl := range out {
		if tl.Name == "semgrep" {
			found = tl.Version == "v1.3.0"
		}
		if strings.ContainsAny(tl.Name, "<>") || len(tl.Name) > maxToolNameLen {
			t.Fatalf("unsafe tool name %q", tl.Name)
		}
	}
	if !found {
		t.Fatalf("semgrep de-dup/version: %+v", out)
	}
}

func TestPipelineAssess(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	zero, two := 0, 2
	day := 24 * time.Hour

	cases := []struct {
		name string
		p    Pipeline
		pol  StatusPolicy
		want PipelineStatus
		fr   Freshness
	}{
		{"never ran", Pipeline{}, StatusPolicy{}, PipelineNever, FreshnessNever},
		{"fresh within floor", Pipeline{LastRunAt: ago(6 * day), LastRunStatus: StatusEvaluated}, StatusPolicy{}, PipelineFresh, FreshnessFresh},
		{"stale after floor", Pipeline{LastRunAt: ago(8 * day)}, StatusPolicy{}, PipelineStale, FreshnessStale},
		{"median widens up to the cap", Pipeline{LastRunAt: ago(20 * day), MedianInterval: 10 * day}, StatusPolicy{}, PipelineFresh, FreshnessFresh},
		{"cap at 30 days", Pipeline{LastRunAt: ago(31 * day), MedianInterval: 20 * day}, StatusPolicy{}, PipelineStale, FreshnessStale},
		{"hourly schedule missed two cycles", Pipeline{LastRunAt: ago(4 * time.Hour), ScheduleInterval: time.Hour}, StatusPolicy{}, PipelineStale, FreshnessStale},
		{"weekly schedule on time", Pipeline{LastRunAt: ago(8 * day), ScheduleInterval: 7 * day}, StatusPolicy{}, PipelineFresh, FreshnessFresh},
		{"running", Pipeline{LastRunAt: ago(time.Minute), LastRunStatus: StatusRunning}, StatusPolicy{}, PipelineRunning, FreshnessRunning},
		{"running too long is not running", Pipeline{LastRunAt: ago(7 * time.Hour), LastRunStatus: StatusRunning}, StatusPolicy{}, PipelineFresh, FreshnessFresh},
		{"archived after 90 days", Pipeline{LastRunAt: ago(91 * day), LastDefaultVerdict: VerdictFail}, StatusPolicy{}, PipelineArchived, FreshnessArchived},
		{"failing beats degraded and stale", Pipeline{LastRunAt: ago(40 * day), LastDefaultVerdict: VerdictFail, LastScanFailures: &two}, StatusPolicy{}, PipelineFailing, FreshnessStale},
		{"scanner errors degrade", Pipeline{LastRunAt: ago(day), LastDefaultVerdict: VerdictPass, LastScanFailures: &two}, StatusPolicy{}, PipelineDegraded, FreshnessFresh},
		{"outdated runner degrades", Pipeline{LastRunAt: ago(day), LastScanFailures: &zero, SensorVersion: "v0.1.0"}, StatusPolicy{MinVersion: "v0.5.0", LatestVersion: "v0.9.0"}, PipelineDegraded, FreshnessFresh},
		{"failing PR gate does not fail the pipeline", Pipeline{LastRunAt: ago(day), LastDefaultVerdict: VerdictPass, LastPRVerdict: VerdictFail}, StatusPolicy{}, PipelineFresh, FreshnessFresh},
		{"revoked wins", Pipeline{LastRunAt: ago(day), RevokedAt: ago(time.Hour)}, StatusPolicy{}, PipelineRevoked, FreshnessFresh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := c.p.Assess(now, c.pol)
			if a.Status != c.want || a.Freshness != c.fr {
				t.Fatalf("Assess = %s/%s, want %s/%s (%+v)", a.Status, a.Freshness, c.want, c.fr, a)
			}
			if a.Status == "offline" {
				t.Fatal("a pipeline is never offline")
			}
		})
	}
	if !PipelineArchived.IsInactive() || PipelineStale.IsInactive() {
		t.Fatal("inactive set")
	}
}
