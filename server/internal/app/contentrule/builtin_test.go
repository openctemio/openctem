package contentrule

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/app/contentrule/builtin"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
)

func builtinEngine(t *testing.T) *contentrule.Engine {
	t.Helper()
	packs, err := builtin.Packs()
	if err != nil || len(packs) != 2 {
		t.Fatalf("packs: %v (%d)", err, len(packs))
	}
	var sets []contentrule.RuleSet
	for _, p := range packs {
		var files []dom.File
		set := contentrule.RuleSet{Kind: contentrule.Kind(p.Kind), Origin: contentrule.Origin{Scope: contentrule.ScopePlatform, Pack: p.Name, Version: p.Release}}
		for name, data := range p.Files {
			files = append(files, dom.File{Path: name, Data: data})
			rules, err := contentrule.ParseFile(data)
			if err != nil {
				t.Fatalf("%s/%s: %v", p.Name, name, err)
			}
			set.Rules = append(set.Rules, rules...)
		}
		// The platform linter accepts the pack as it is: every rule valid,
		// unique ids, no credential-shaped text, T0.
		rep := contentpack.Lint(context.Background(), p.Kind, files)
		if len(rep.Errors) > 0 || len(rep.Secrets) > 0 || rep.Tier != dom.TierT0 || rep.Items != len(set.Rules) {
			t.Fatalf("%s lint: errors=%v secrets=%v tier=%s items=%d/%d", p.Name, rep.Errors, rep.Secrets, rep.Tier, rep.Items, len(set.Rules))
		}
		sets = append(sets, set)
	}
	e, errs := contentrule.Compile(sets)
	if len(errs) > 0 {
		t.Fatalf("compile: %v", errs)
	}
	return e
}

func TestBuiltinPacksLintCompileAndArchiveDeterministically(t *testing.T) {
	builtinEngine(t)
	packs, _ := builtin.Packs()
	for _, p := range packs {
		a, err := p.Archive()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := p.Archive()
		if string(a) != string(b) {
			t.Errorf("%s archive is not deterministic", p.Name)
		}
		arc, err := dom.Canonicalize(strings.NewReader(string(a)), dom.PlatformLimits)
		if err != nil || len(arc.Files) == 0 {
			t.Errorf("%s canonicalize: %v", p.Name, err)
		}
	}
}

func TestBuiltinFingerprints(t *testing.T) {
	e := builtinEngine(t)
	res := e.Scan(context.Background(), contentrule.Document{
		URL:     "https://www.example.com/",
		Headers: map[string]string{"server": "nginx/1.25.3"},
		Cookies: []string{"PHPSESSID", "wordpress_logged_in_abc"},
		Scripts: []string{"/wp-includes/js/jquery/jquery-3.7.1.min.js", "/_next/static/chunks/app.js"},
		Body:    []byte(`<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>`),
		Title:   "Grafana",
	}, contentrule.DefaultBudget, nil)
	got := map[string]contentrule.TechMatch{}
	for _, tm := range res.Technologies {
		got[tm.RuleID] = tm
	}
	want := map[string]string{"nginx": "1.25.3", "php": "", "wordpress": "6.4.2", "jquery": "3.7.1", "nextjs": "", "grafana": ""}
	for id, v := range want {
		tm, ok := got[id]
		if !ok || tm.Version != v {
			t.Errorf("%s = %+v (ok=%v), want version %q", id, tm, ok, v)
		}
	}
	if got["nginx"].CPE != "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*" {
		t.Errorf("nginx cpe = %q", got["nginx"].CPE)
	}
	if _, ok := got["apache-http-server"]; ok {
		t.Error("apache matched an nginx server")
	}
}

func TestBuiltinSecretsAreFoundAndMasked(t *testing.T) {
	e := builtinEngine(t)
	// Values are built at run time: no credential-shaped literal in the repo.
	gh := "ghp_" + strings.Repeat("Ab3", 12)
	aws := "AKIA" + strings.Repeat("Q7", 8)
	body := "var cfg = {token: '" + gh + "', key: '" + aws + "', api: 'https://svc.corp/api'};\n" +
		"fetch('postgres://app:" + "s3cr3tpass" + "@db.example.com/main')"
	res := e.Scan(context.Background(), contentrule.Document{URL: "https://www.example.com/app.js", Body: []byte(body)},
		contentrule.DefaultBudget, func(v string) string { return "k" })
	got := map[string]contentrule.SecretMatch{}
	for _, s := range res.Secrets {
		got[s.RuleID] = s
		for _, v := range []string{gh, aws, "s3cr3tpass"} {
			if strings.Contains(s.Preview, v) || s.Length == 0 {
				t.Errorf("%s: preview %q holds a value", s.RuleID, s.Preview)
			}
		}
	}
	for _, id := range []string{"github-token", "aws-access-key-id", "internal-hostname", "credentials-in-url"} {
		if _, ok := got[id]; !ok {
			t.Errorf("%s not found in %+v", id, res.Secrets)
		}
	}
	if got["credentials-in-url"].Preview != "s3…ss" {
		t.Errorf("credentials preview = %q", got["credentials-in-url"].Preview)
	}
}
