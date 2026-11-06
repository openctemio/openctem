package contentsource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestValidateGitURL(t *testing.T) {
	ok := map[string]string{
		"https://gitlab.acme.example/appsec/rules.git":      "gitlab.acme.example",
		"https://GitLab.Acme.Example:443/appsec/rules.git":  "gitlab.acme.example",
		"https://gitlab.acme.example:8443/appsec/rules.git": "gitlab.acme.example:8443",
	}
	for in, host := range ok {
		got, err := ValidateGitURL(in)
		if err != nil || got != host {
			t.Errorf("%s: %q %v, want %q", in, got, err, host)
		}
	}
	for _, in := range []string{
		"", "http://gitlab.example.com/a.git", "ssh://git@gitlab.example.com/a.git", "git@gitlab.example.com:a/b.git",
		"file:///etc", "/srv/repo", "https://user:tok@gitlab.example.com/a.git", "https://user@gitlab.example.com/a.git",
		"https://gitlab.example.com/a.git?x=1", "https:///a.git", "git://gitlab.example.com/a.git",
	} {
		if _, err := ValidateGitURL(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestValidateRefAndPath(t *testing.T) {
	for _, r := range []string{"main", "release/1.2", "v1.0.0", strings.Repeat("a", 40)} {
		if err := ValidateRef(r); err != nil {
			t.Errorf("%q: %v", r, err)
		}
	}
	for _, r := range []string{"", "-x", "a..b", "a b", "a:b", "/x", "x/", "x.lock", "a@{1}", "a\\b"} {
		if err := ValidateRef(r); err == nil {
			t.Errorf("%q accepted", r)
		}
	}
	if !IsUpstreamRevision(strings.Repeat("ab", 20)) || IsUpstreamRevision("main") {
		t.Error("IsUpstreamRevision")
	}
	for in, want := range map[string]string{"": "", ".": "", "/rules/": "rules", "a//b/./c": "a/b/c"} {
		if got, err := CleanRepoPath(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"../x", "a/../../b", "a\\b", "a\x00"} {
		if _, err := CleanRepoPath(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestSlugAndNamespace(t *testing.T) {
	for _, s := range []string{"acme-sast", "ab", "x1", strings.Repeat("a", 40)} {
		if err := ValidateSlug(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	// '@' is reserved for the platform namespace.
	for _, s := range []string{"", "a", "a-", "@acme", "acme/sast", "acme:sast", "Acme", "-a", "a_b", "a.b", strings.Repeat("a", 41)} {
		if err := ValidateSlug(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	tenant := &Source{Scope: ScopeTenant, Slug: "acme", RuleNamespace: "acme"}
	platform := &Source{Scope: ScopePlatform, Slug: "central"}
	official := &Source{Scope: ScopePlatform, Slug: "openctem", Official: true}
	if tenant.Namespace() != "acme" || platform.Namespace() != "@central" || official.Namespace() != "" {
		t.Fatal(tenant.Namespace(), platform.Namespace(), official.Namespace())
	}
}

func TestResolveUsername(t *testing.T) {
	cases := []struct{ user, token, want string }{
		{"", "glpat-abcdefgh", "oauth2"},
		{"", "ghp_abcdefgh", "x-access-token"},
		{"", "github_pat_abcdefgh", "x-access-token"},
		{"", "opaque-token-1", "oauth2"},
		{"gitlab+deploy-token-3", "gldt-abcdefgh", "gitlab+deploy-token-3"},
	}
	for _, c := range cases {
		if got, err := ResolveUsername(c.user, c.token); err != nil || got != c.want {
			t.Errorf("%q/%q: %q %v, want %q", c.user, c.token, got, err, c.want)
		}
	}
	if _, err := ResolveUsername("", "gldt-abcdefgh"); !errors.Is(err, ErrUsernameRequired) {
		t.Errorf("deploy token without username: %v", err)
	}
	if _, err := ResolveUsername("a:b", "glpat-abcdefgh"); err == nil {
		t.Error("username with ':' accepted")
	}
	if err := ValidateToken("short"); err == nil {
		t.Error("short token accepted")
	}
	if err := ValidateToken("has space here"); err == nil {
		t.Error("token with a space accepted")
	}
	if TokenHint("glpat-abcdefgh") != "efgh" || TokenHint("abc") != "" {
		t.Error("TokenHint")
	}
}

func TestSetGitClearsCredentialOnHostChange(t *testing.T) {
	now := time.Now()
	s, err := NewTenantSource(shared.NewID(), "acme", "Acme", KindSemgrepRules, GitConfig{URL: "https://a.example.com/r.git", Ref: "main"}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	s.SetCredential("oauth2", "sealed", "abcd", now)
	if changed, err := s.SetGit(GitConfig{URL: "https://a.example.com/other.git", Ref: "dev", Path: "x"}); err != nil || changed || !s.HasCredential() {
		t.Fatalf("same host: changed %v err %v cred %v", changed, err, s.HasCredential())
	}
	if changed, err := s.SetGit(GitConfig{URL: "https://b.example.com/r.git", Ref: "dev"}); err != nil || !changed || s.HasCredential() {
		t.Fatalf("new host: changed %v err %v cred %v", changed, err, s.HasCredential())
	}
	s.SetCredential("oauth2", "sealed", "abcd", now)
	if changed, _ := s.SetGit(GitConfig{URL: "https://b.example.com:8443/r.git", Ref: "dev"}); !changed {
		t.Fatal("a new port is a new destination")
	}
}

func TestSetSchedule(t *testing.T) {
	now := time.Now()
	s := &Source{}
	if err := s.SetSchedule(10, 0, now); err != nil || s.SyncIntervalMin != 10 || s.NextSyncAt == nil {
		t.Fatalf("10 minutes: %v", err)
	}
	if err := s.SetSchedule(4, 0, now); err == nil {
		t.Fatal("under the instance floor accepted")
	}
	if err := s.SetSchedule(30, 60, now); err == nil {
		t.Fatal("under the organization floor accepted")
	}
	if err := s.SetSchedule(0, 60, now); err != nil || s.NextSyncAt != nil {
		t.Fatalf("off: %v", err)
	}
	if err := s.SetSchedule(MaxSyncIntervalMinutes+1, 0, now); err == nil {
		t.Fatal("over a week accepted")
	}
	s.SyncIntervalMin = 60
	next := s.NextScheduled(now, 0.999)
	if next.Before(now.Add(time.Hour)) || next.After(now.Add(time.Hour+6*time.Minute)) {
		t.Fatalf("jitter: %v", next.Sub(now))
	}
}

func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "acme ca"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestValidateCAPEM(t *testing.T) {
	good := selfSignedPEM(t)
	if err := ValidateCAPEM(good + good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"not pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", good + "trailing"} {
		if err := ValidateCAPEM(bad); err == nil {
			t.Errorf("%q accepted", bad[:min(len(bad), 30)])
		}
	}
}

func TestVisibility(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	own := &Source{Scope: ScopeTenant, TenantID: &a}
	if !own.VisibleTo(a) || own.VisibleTo(b) {
		t.Fatal("tenant source visibility")
	}
	for avail, want := range map[Availability]bool{AvailabilityDefaultOn: true, AvailabilityOptIn: true, AvailabilityHidden: false} {
		p := &Source{Scope: ScopePlatform, Availability: avail}
		if p.VisibleTo(a) != want || p.BelongsTo(a) {
			t.Errorf("platform %s visible %v", avail, p.VisibleTo(a))
		}
	}
}

func TestExtractRulesAndDiff(t *testing.T) {
	files := []contentpack.File{
		{Path: "a.yaml", Data: []byte("rules:\n  - id: r1\n    pattern: a()\n  - id: r2\n    pattern: b()\n")},
		{Path: "b.yml", Data: []byte("rules:\n  - id: r2\n    pattern: c()\n")},
		{Path: "README.md", Data: []byte("rules:\n  - id: ignored\n")},
		{Path: "bad.yaml", Data: []byte("{{{")},
	}
	rules, dup := ExtractRules(KindSemgrepRules, files)
	if len(rules) != 2 || !dup {
		t.Fatalf("rules %v dup %v", rules, dup)
	}
	n, _ := ExtractRules(KindNucleiTemplates, []contentpack.File{{Path: "t.yaml", Data: []byte("id: cve-1\ninfo: {}\n")}})
	if len(n) != 1 || n[0].ID != "cve-1" {
		t.Fatalf("nuclei: %v", n)
	}
	w, _ := ExtractRules(KindWordlist, []contentpack.File{{Path: "w.txt", Data: []byte("a\n")}})
	if len(w) != 1 || w[0].ID != "w.txt" {
		t.Fatalf("wordlist: %v", w)
	}

	base := &Snapshot{ID: shared.NewID(), Tier: contentpack.TierT0, RuleCount: 3, Rules: []Rule{{ID: "r1", SHA256: "1"}, {ID: "r2", SHA256: "2"}, {ID: "r3", SHA256: "3"}}}
	d := ComputeDiff(base, []Rule{{ID: "r1", SHA256: "1"}, {ID: "r2", SHA256: "x"}, {ID: "r4", SHA256: "4"}}, contentpack.TierT0, "")
	if strings.Join(d.Added, ",") != "r4" || strings.Join(d.Removed, ",") != "r3" || strings.Join(d.Changed, ",") != "r2" {
		t.Fatalf("diff: %+v", d)
	}
	first := ComputeDiff(nil, []Rule{{ID: "r1"}}, contentpack.TierT0, "")
	if first.AddedCount != 1 || first.RemovedCount != 0 || first.BaseSnapshotID != "" {
		t.Fatalf("first diff: %+v", first)
	}
}

func TestEvaluatePromotion(t *testing.T) {
	base := &Snapshot{Tier: contentpack.TierT0, RuleCount: 20, LicenseSPDX: "MIT"}
	cand := func(tier contentpack.Tier, license string, removed int) *Snapshot {
		return &Snapshot{Tier: tier, LicenseSPDX: license, Diff: Diff{RemovedCount: removed}}
	}
	cases := []struct {
		name    string
		policy  PromotionPolicy
		base    *Snapshot
		cand    *Snapshot
		dup     bool
		auto    bool
		review  bool
		blocked string
	}{
		{"clean", PolicyAuto, base, cand(contentpack.TierT0, "MIT", 1), false, true, false, ""},
		{"review policy", PolicyReview, base, cand(contentpack.TierT0, "MIT", 0), false, false, true, CheckPolicyReview},
		{"tier raised forces review", PolicyAuto, base, cand(contentpack.TierT2, "MIT", 0), false, false, true, CheckTierRaised},
		{"first snapshot above T0", PolicyAuto, nil, cand(contentpack.TierT1, "", 0), false, false, true, CheckTierRaised},
		{"license changed", PolicyAuto, base, cand(contentpack.TierT0, "Apache-2.0", 0), false, false, false, CheckLicenseChanged},
		{"no-service license", PolicyAuto, nil, cand(contentpack.TierT0, "LicenseRef-Semgrep-Rules", 0), false, false, false, CheckLicenseNoService},
		{"mass removal", PolicyAuto, base, cand(contentpack.TierT0, "MIT", 6), false, false, false, CheckMassRemoval},
		{"duplicate ids", PolicyAuto, base, cand(contentpack.TierT0, "MIT", 0), true, false, false, CheckDuplicateRuleIDs},
	}
	for _, c := range cases {
		checks, review := EvaluatePromotion(c.policy, c.base, c.cand, c.dup)
		if checks.AutoPromote != c.auto || review != c.review {
			t.Errorf("%s: auto %v review %v (%v)", c.name, checks.AutoPromote, review, checks.Blocked)
		}
		if c.blocked != "" && !strings.Contains(strings.Join(checks.Blocked, ","), c.blocked) {
			t.Errorf("%s: blocked %v, want %s", c.name, checks.Blocked, c.blocked)
		}
	}
}

func TestDetectLicense(t *testing.T) {
	for text, want := range map[string]string{
		"":                                    "",
		"MIT License\n\nPermission is hereby": "MIT",
		"Apache License\nVersion 2.0, January 2004": "Apache-2.0",
		"Semgrep Rules License v1.0":                "LicenseRef-Semgrep-Rules",
		"... with the Commons Clause ...":           "LicenseRef-Commons-Clause",
		"all rights reserved":                       "LicenseRef-Unknown",
	} {
		if got := DetectLicense([]byte(text)); got != want {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
}
