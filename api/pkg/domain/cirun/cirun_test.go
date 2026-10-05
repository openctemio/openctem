package cirun

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func githubClaims(over map[string]any) Claims {
	m := map[string]any{
		"iss": GitHubIssuer, "sub": "repo:Acme/API:ref:refs/heads/main", "jti": "j1",
		"repository": "Acme/API", "repository_id": "42", "ref": "refs/heads/main", "ref_type": "branch",
		"sha": "ABCDEF1234567", "actor": "octocat", "run_id": "999", "run_attempt": "1",
		"workflow_ref": "Acme/API/.github/workflows/ci.yml@refs/heads/main", "event_name": "push",
	}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return ParseGitHubClaims(m)
}

func TestParseGitHubClaims(t *testing.T) {
	c := githubClaims(nil)
	if c.Repository != "acme/api" || c.Owner() != "acme" || c.Branch != "main" || c.SHA != "abcdef1234567" ||
		c.RunID != "999" || c.Event != "push" || c.PullRequest != "" {
		t.Fatalf("push claims = %+v", c)
	}
	pr := githubClaims(map[string]any{"ref": "refs/pull/17/merge", "head_ref": "feature/x", "base_ref": "main", "event_name": "pull_request"})
	if pr.PullRequest != "17" || pr.Branch != "feature/x" || pr.RefName() != "feature/x" {
		t.Fatalf("pull request claims = %+v", pr)
	}
	tag := githubClaims(map[string]any{"ref": "refs/tags/v1.2.0", "ref_type": "tag"})
	if tag.Branch != "" || tag.RefName() != "v1.2.0" {
		t.Fatalf("tag claims = %+v", tag)
	}
	if got := PipelineURL(ProviderGitHub, GitHubIssuer, c); got != "https://github.com/acme/api/actions/runs/999" {
		t.Fatalf("pipeline url = %q", got)
	}
	if got := CanonicalRepository(ProviderGitHub, GitHubIssuer, c.Repository); got != "github.com/acme/api" {
		t.Fatalf("canonical = %q", got)
	}
}

func TestParseGitLabClaims(t *testing.T) {
	base := map[string]any{
		"iss": "https://gitlab.example.com", "sub": "project_path:grp/sub/proj:ref_type:branch:ref:main", "jti": "j",
		"project_path": "Grp/Sub/Proj", "project_id": 7.0, "namespace_path": "grp/sub", "ref": "main", "ref_type": "branch",
		"ref_protected": "true", "sha": "abc1234", "user_login": "dev", "pipeline_id": 123.0, "pipeline_source": "push",
	}
	c := ParseGitLabClaims(base)
	if c.Repository != "grp/sub/proj" || c.Owner() != "grp" || c.Ref != "refs/heads/main" || c.Branch != "main" ||
		!c.RefProtected || c.RunID != "123" || c.RepositoryID != "7" {
		t.Fatalf("gitlab claims = %+v", c)
	}
	if got := CanonicalRepository(ProviderGitLab, "https://gitlab.example.com", c.Repository); got != "gitlab.example.com/grp/sub/proj" {
		t.Fatalf("canonical = %q", got)
	}
	if got := PipelineURL(ProviderGitLab, "https://gitlab.example.com", c); got != "https://gitlab.example.com/grp/sub/proj/-/pipelines/123" {
		t.Fatalf("pipeline url = %q", got)
	}
	// A detached merge request pipeline never claims a real branch.
	base["ref"] = "refs/merge-requests/5/head"
	base["pipeline_source"] = "merge_request_event"
	mr := ParseGitLabClaims(base)
	if mr.PullRequest != "5" || mr.Branch != "merge-requests/5" {
		t.Fatalf("merge request claims = %+v", mr)
	}
	base["ref"], base["ref_type"] = "v1", "tag"
	if tag := ParseGitLabClaims(base); tag.Ref != "refs/tags/v1" || tag.Branch != "" {
		t.Fatalf("tag = %+v", tag)
	}
}

func TestRulesAdmit(t *testing.T) {
	c := githubClaims(nil)
	cases := []struct {
		name  string
		rules Rules
		claim Claims
		want  string // refusal code, "" admits
	}{
		{"owner", Rules{Owners: []string{"acme"}}, c, ""},
		{"other owner", Rules{Owners: []string{"evil"}}, c, RefuseOwner},
		{"exact repository", Rules{Repositories: []string{"acme/api"}}, c, ""},
		{"wildcard repository", Rules{Repositories: []string{"acme/*"}}, c, ""},
		{"wrong repository", Rules{Repositories: []string{"acme/web"}}, c, RefuseRepository},
		{"one-level wildcard does not cross a slash", Rules{Repositories: []string{"grp/*"}},
			Claims{Repository: "grp/sub/proj", SHA: "a", Ref: "refs/heads/main", JTI: "j"}, RefuseRepository},
		{"deep wildcard", Rules{Repositories: []string{"grp/**"}},
			Claims{Repository: "grp/sub/proj", SHA: "a", Ref: "refs/heads/main", JTI: "j"}, ""},
		{"ref by name", Rules{Owners: []string{"acme"}, Refs: []string{"main"}}, c, ""},
		{"ref by full name", Rules{Owners: []string{"acme"}, Refs: []string{"refs/heads/main"}}, c, ""},
		{"ref pattern", Rules{Owners: []string{"acme"}, Refs: []string{"release/*"}}, githubClaims(map[string]any{"ref": "refs/heads/release/1.0"}), ""},
		{"ref not listed", Rules{Owners: []string{"acme"}, Refs: []string{"main"}}, githubClaims(map[string]any{"ref": "refs/heads/dev"}), RefuseRef},
		{"environment required", Rules{Owners: []string{"acme"}, Environments: []string{"prod"}}, c, RefuseEnvironment},
		{"environment matches", Rules{Owners: []string{"acme"}, Environments: []string{"prod"}}, githubClaims(map[string]any{"environment": "prod"}), ""},
		{"event not listed", Rules{Owners: []string{"acme"}, Events: []string{"pull_request"}}, c, RefuseEvent},
		{"fork event refused by default", Rules{Owners: []string{"acme"}}, githubClaims(map[string]any{"event_name": "pull_request_target"}), RefuseForkPullRequest},
		{"workflow_run refused by default", Rules{Owners: []string{"acme"}}, githubClaims(map[string]any{"event_name": "workflow_run"}), RefuseForkPullRequest},
		{"fork event when allowed", Rules{Owners: []string{"acme"}, AllowForkPullRequests: true}, githubClaims(map[string]any{"event_name": "pull_request_target"}), ""},
		{"protected ref required", Rules{Owners: []string{"acme"}, RequireProtectedRef: true}, c, RefuseRefNotProtected},
		{"missing sha", Rules{Owners: []string{"acme"}}, githubClaims(map[string]any{"sha": nil}), RefuseMissingClaims},
		{"missing jti", Rules{Owners: []string{"acme"}}, githubClaims(map[string]any{"jti": nil}), RefuseMissingClaims},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rules.normalized().Admit(tc.claim)
			got := ""
			if r != nil {
				got = r.Code
			}
			if got != tc.want {
				t.Fatalf("refusal = %q (%v), want %q", got, r, tc.want)
			}
		})
	}
}

func TestTrustConfigValidate(t *testing.T) {
	tid := shared.NewID()
	ok := func() *TrustConfig {
		c := &TrustConfig{TenantID: tid, Name: "gh", Provider: ProviderGitHub, Rules: Rules{Owners: []string{"Acme"}}}
		c.Normalize()
		return c
	}
	c := ok()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Issuer != GitHubIssuer || c.Audience != DefaultAudience(tid) || c.DefaultBranch != "main" || c.Rules.Owners[0] != "acme" {
		t.Fatalf("defaults = %+v", c)
	}
	bad := map[string]func(c *TrustConfig){
		"no owner or repository":  func(c *TrustConfig) { c.Rules = Rules{Refs: []string{"main"}} },
		"wildcard owner":          func(c *TrustConfig) { c.Rules = Rules{Repositories: []string{"*/api"}} },
		"owner with slash":        func(c *TrustConfig) { c.Rules = Rules{Owners: []string{"a/b"}} },
		"repository without name": func(c *TrustConfig) { c.Rules = Rules{Repositories: []string{"acme"}} },
		"github foreign issuer":   func(c *TrustConfig) { c.Issuer = "https://evil.example" },
		"gitlab http issuer":      func(c *TrustConfig) { c.Provider, c.Issuer = ProviderGitLab, "http://gitlab.local" },
		"gitlab issuer with user": func(c *TrustConfig) { c.Provider, c.Issuer = ProviderGitLab, "https://u:p@gitlab.local" },
		"unknown provider":        func(c *TrustConfig) { c.Provider = "jenkins" },
		"audience with space":     func(c *TrustConfig) { c.Audience = "a b" },
		"empty name":              func(c *TrustConfig) { c.Name = "" },
		"pattern default branch":  func(c *TrustConfig) { c.DefaultBranch = "ma*" },
		"bad ref pattern":         func(c *TrustConfig) { c.Rules.Refs = []string{"[unterminated"} },
	}
	for name, f := range bad {
		t.Run(name, func(t *testing.T) {
			c := ok()
			f(c)
			if err := c.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want validation", err)
			}
		})
	}
	gl := &TrustConfig{TenantID: tid, Name: "gl", Provider: ProviderGitLab, Issuer: "https://gitlab.example.com/", Rules: Rules{Owners: []string{"grp"}}}
	gl.Normalize()
	if err := gl.Validate(); err != nil || gl.Issuer != "https://gitlab.example.com" {
		t.Fatalf("self-managed gitlab: %v %q", err, gl.Issuer)
	}
}

func TestTokens(t *testing.T) {
	tok, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, TokenPrefix) || !LooksLikeToken(tok) || string(HashToken(tok)) != string(hash) {
		t.Fatalf("token %q", tok)
	}
	tok2, _, _ := NewToken()
	if tok == tok2 {
		t.Fatal("tokens repeat")
	}
	for _, bad := range []string{"", "octci_", "octs_" + strings.Repeat("a", 43), TokenPrefix + strings.Repeat("a", 200)} {
		if LooksLikeToken(bad) {
			t.Fatalf("%q looks like a token", bad)
		}
	}
}

func f64(v float64) *float64 { return &v }

func TestEvaluate(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	def := DefaultGatePolicy()
	high := RunFinding{ID: shared.NewID(), Fingerprint: "high", Severity: "high", Status: "new"}
	med := RunFinding{ID: shared.NewID(), Fingerprint: "med", Severity: "medium", Status: "new"}
	oldHigh := RunFinding{ID: shared.NewID(), Fingerprint: "old", Severity: "critical", Status: "confirmed"}
	secret := RunFinding{ID: shared.NewID(), Fingerprint: "secret", Severity: "low", FindingType: "secret", Status: "confirmed"}
	kev := RunFinding{ID: shared.NewID(), Fingerprint: "kev", Severity: "low", IsInKEV: true, Status: "new"}
	epss := RunFinding{ID: shared.NewID(), Fingerprint: "epss", Severity: "low", EPSSScore: f64(0.8), Status: "new"}
	accepted := RunFinding{ID: shared.NewID(), Fingerprint: "acc", Severity: "critical", Status: "accepted", AcceptanceExpiresAt: &future}
	expired := RunFinding{ID: shared.NewID(), Fingerprint: "exp", Severity: "critical", Status: "accepted", AcceptanceExpiresAt: &past}
	suppressed := RunFinding{ID: shared.NewID(), Fingerprint: "sup", Severity: "critical", Status: "new", Suppressed: true}
	fp := RunFinding{ID: shared.NewID(), Fingerprint: "fp", Severity: "critical", FindingType: "secret", Status: "false_positive"}
	newSet := func(fps ...string) map[string]bool {
		m := map[string]bool{}
		for _, f := range fps {
			m[f] = true
		}
		return m
	}
	eval := func(p GatePolicy, fs []RunFinding, n map[string]bool) GateVerdict {
		return Evaluate(GateInput{Policy: p, PolicySource: ScopeDefault, Findings: fs, NewFingerprints: n,
			BaselineKnown: n != nil, BaselineBranch: "main", Now: now})
	}

	// A pull request that adds a high finding fails.
	if v := eval(def, []RunFinding{high}, newSet("high")); v.Verdict != VerdictFail || v.Reasons[0].Code != ReasonSeverity {
		t.Fatalf("new high: %+v", v)
	}
	// Old findings on the default branch do not fail a new-only policy.
	if v := eval(def, []RunFinding{oldHigh, med}, newSet("med")); v.Verdict != VerdictPass || v.Summary.PreExisting != 1 {
		t.Fatalf("pre-existing critical under new-only: %+v", v)
	}
	// ... but do when the policy judges everything.
	all := def
	all.NewFindingsOnly = false
	if v := eval(all, []RunFinding{oldHigh}, newSet()); v.Verdict != VerdictFail {
		t.Fatalf("pre-existing critical, all findings: %+v", v)
	}
	// A committed secret always fails: old, low severity, any threshold.
	none := def
	none.FailOnSeverity, none.FailOnKEV = SeverityNone, false
	if v := eval(none, []RunFinding{secret}, newSet()); v.Verdict != VerdictFail || v.Reasons[0].Code != ReasonSecret {
		t.Fatalf("pre-existing secret: %+v", v)
	}
	// Accepted risk, suppressions and false positives are honored;
	// expired acceptance is not.
	if v := eval(def, []RunFinding{accepted, suppressed, fp}, newSet("acc", "sup", "fp")); v.Verdict != VerdictPass || v.Summary.Accepted != 3 {
		t.Fatalf("honored: %+v", v)
	}
	if v := eval(def, []RunFinding{expired}, newSet("exp")); v.Verdict != VerdictFail {
		t.Fatalf("expired acceptance: %+v", v)
	}
	// KEV and EPSS.
	if v := eval(def, []RunFinding{kev}, newSet("kev")); v.Verdict != VerdictFail || v.Reasons[0].Code != ReasonKEV {
		t.Fatalf("kev: %+v", v)
	}
	withEPSS := def
	withEPSS.EPSSThreshold = f64(0.5)
	if v := eval(withEPSS, []RunFinding{epss}, newSet("epss")); v.Verdict != VerdictFail || v.Reasons[0].Code != ReasonEPSS {
		t.Fatalf("epss: %+v", v)
	}
	if v := eval(def, []RunFinding{epss}, newSet("epss")); v.Verdict != VerdictPass {
		t.Fatalf("epss without threshold: %+v", v)
	}
	// No baseline: every finding counts as new (fail closed), with a note.
	v := eval(def, []RunFinding{oldHigh}, nil)
	if v.Verdict != VerdictFail || v.Baseline.Known || v.Reasons[len(v.Reasons)-1].Code != ReasonNoBaseline {
		t.Fatalf("no baseline: %+v", v)
	}
	// Scan failures fail.
	if v := Evaluate(GateInput{Policy: def, ScanFailures: 1, Now: now}); v.Verdict != VerdictFail || v.Reasons[0].Code != ReasonScanFailure {
		t.Fatalf("scan failure: %+v", v)
	}
	// Warn mode passes and says it would fail.
	warn := def
	warn.Mode = ModeWarn
	if v := eval(warn, []RunFinding{high}, newSet("high")); v.Verdict != VerdictPass || !v.WouldFail {
		t.Fatalf("warn: %+v", v)
	}
	// Break-glass passes a failing run while active, not once revoked or expired.
	o := &GateOverride{ID: shared.NewID(), Reason: "hotfix for outage", CreatedByEmail: "admin@acme.io", ExpiresAt: future}
	v = Evaluate(GateInput{Policy: def, Findings: []RunFinding{high}, NewFingerprints: newSet("high"), Override: o, Now: now})
	if v.Verdict != VerdictPass || v.Override == nil || !v.WouldFail {
		t.Fatalf("override: %+v", v)
	}
	o.RevokedAt = &now
	if v := Evaluate(GateInput{Policy: def, Findings: []RunFinding{high}, NewFingerprints: newSet("high"), Override: o, Now: now}); v.Verdict != VerdictFail {
		t.Fatalf("revoked override: %+v", v)
	}
	// Reasons are capped; the summary counts everything.
	many := make([]RunFinding, 0, 80)
	for i := range 80 {
		many = append(many, RunFinding{Fingerprint: strings.Repeat("x", i+1), Severity: "critical", Status: "new"})
	}
	if v := eval(all, many, nil); len(v.Reasons) > maxReasons+1 || v.Summary.Blocking != 80 {
		t.Fatalf("cap: %d reasons, %d blocking", len(v.Reasons), v.Summary.Blocking)
	}
}

func TestStrictestAndPolicyValidate(t *testing.T) {
	a := GatePolicy{Mode: ModeWarn, FailOnSeverity: "critical", NewFindingsOnly: true, EPSSThreshold: f64(0.9)}
	b := GatePolicy{Mode: ModeEnforce, FailOnSeverity: "medium", NewFindingsOnly: false, FailOnKEV: true, EPSSThreshold: f64(0.3)}
	s := Strictest([]GatePolicy{a, b})
	if s.Mode != ModeEnforce || s.FailOnSeverity != "medium" || s.NewFindingsOnly || !s.FailOnKEV || *s.EPSSThreshold != 0.3 {
		t.Fatalf("strictest = %+v", s)
	}
	id := shared.NewID()
	good := GatePolicy{ScopeType: ScopeRepository, ScopeID: &id, Mode: ModeEnforce, FailOnSeverity: "high"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]GatePolicy{
		"tenant with id":    {ScopeType: ScopeTenant, ScopeID: &id, Mode: ModeEnforce, FailOnSeverity: "high"},
		"repository no id":  {ScopeType: ScopeRepository, Mode: ModeEnforce, FailOnSeverity: "high"},
		"bad scope":         {ScopeType: "org", Mode: ModeEnforce, FailOnSeverity: "high"},
		"bad mode":          {ScopeType: ScopeTenant, Mode: "audit", FailOnSeverity: "high"},
		"info threshold":    {ScopeType: ScopeTenant, Mode: ModeEnforce, FailOnSeverity: "info"},
		"epss out of range": {ScopeType: ScopeTenant, Mode: ModeEnforce, FailOnSeverity: "high", EPSSThreshold: f64(1.5)},
	} {
		if err := p.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestOverrideValidate(t *testing.T) {
	now := time.Now()
	o := GateOverride{CommitSHA: " ABCDEF1 ", Reason: "production outage fix", ExpiresAt: now.Add(time.Hour)}
	if err := o.Validate(now); err != nil || o.CommitSHA != "abcdef1" {
		t.Fatalf("%v %q", err, o.CommitSHA)
	}
	if !o.MatchesCommit("abcdef1234") || o.MatchesCommit("abcdee1") {
		t.Fatal("commit prefix matching")
	}
	for name, bad := range map[string]GateOverride{
		"not a sha":    {CommitSHA: "main", Reason: "production outage fix", ExpiresAt: now.Add(time.Hour)},
		"short reason": {CommitSHA: "abcdef1", Reason: "because", ExpiresAt: now.Add(time.Hour)},
		"too long":     {CommitSHA: "abcdef1", Reason: "production outage fix", ExpiresAt: now.Add(8 * 24 * time.Hour)},
		"in the past":  {CommitSHA: "abcdef1", Reason: "production outage fix", ExpiresAt: now.Add(-time.Minute)},
	} {
		if err := bad.Validate(now); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// The job id comes from the verified token: GitHub check_run_id, GitLab job_id.
func TestClaimsJobID(t *testing.T) {
	if c := githubClaims(map[string]any{"check_run_id": "777"}); c.JobID != "777" {
		t.Fatalf("github job id = %q", c.JobID)
	}
	gl := ParseGitLabClaims(map[string]any{"project_path": "grp/proj", "ref": "main", "job_id": 4242.0})
	if gl.JobID != "4242" {
		t.Fatalf("gitlab job id = %q", gl.JobID)
	}
}
