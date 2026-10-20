package platformai

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
)

const apiKey = "sk-ant-test-key-0123456789"

func newSvc(t *testing.T, envLocked bool) (*Service, *cst.Repo, *cst.Audit, *cst.Notifier) {
	t.Helper()
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	return NewService(repo, cst.Cipher(t), cst.Recorder(audit, n), envLocked, "claude", "env-model", nil), repo, audit, n
}

// Off by default; the key is encrypted, never returned, never audited; the
// change is critical and told to every administrator; it applies at once.
func TestOffByDefaultAndKeyWriteOnly(t *testing.T) {
	svc, repo, audit, n := newSvc(t, false)
	ctx := context.Background()
	if svc.Enabled(ctx) {
		t.Fatal("platform AI must be off by default")
	}
	got, err := svc.Update(ctx, cst.SuperAdmin(t), Input{Enabled: true, Provider: "claude", Model: "claude-sonnet-4", APIKey: cst.Strp(apiKey), Reason: "offer platform AI"}, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || !got.KeySet || got.Provider != "claude" {
		t.Fatalf("got %+v", got)
	}
	for _, where := range []string{repo.Raw(SettingKey), audit.JSON(t), n.All()} {
		if strings.Contains(where, apiKey) {
			t.Fatal("the key leaked")
		}
	}
	p, m, k, ok := svc.PlatformAI(ctx)
	if !ok || p != "claude" || m != "claude-sonnet-4" || k != apiKey {
		t.Fatalf("the client must get the console configuration at once: %s %s %v", p, m, ok)
	}
	if len(audit.Entries) != 1 || n.Count() != 1 {
		t.Fatalf("audit %d notices %d", len(audit.Entries), n.Count())
	}
}

// The environment pins the provider.
func TestEnvironmentLocks(t *testing.T) {
	svc, _, audit, _ := newSvc(t, true)
	ctx := context.Background()
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{Provider: "openai", Reason: "x"}, 0, "", ""); !errors.Is(err, ErrLockedByEnvironment) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := svc.Get(ctx); !got.LockedByEnvironment || got.Model != "env-model" {
		t.Fatalf("got %+v", got)
	}
	if _, _, _, ok := svc.PlatformAI(ctx); ok {
		t.Fatal("the console configuration is never used while the environment pins it")
	}
	if len(audit.Entries) != 0 {
		t.Fatal("a refused change writes nothing")
	}
}

// Turning it on needs provider, model and key; a provider switch drops the
// old provider's key; unknown providers and a missing reason are refused.
func TestValidation(t *testing.T) {
	svc, _, _, _ := newSvc(t, false)
	ctx := context.Background()
	actor := cst.SuperAdmin(t)
	if _, err := svc.Update(ctx, actor, Input{Enabled: true, Provider: "claude", Model: "m", Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("on without a key: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "skynet", Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown provider: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "m"}, 0, "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "m", APIKey: cst.Strp(apiKey), Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Update(ctx, actor, Input{Provider: "openai", Model: "gpt", Reason: "switch"}, 1, "", "")
	if err != nil || got.KeySet {
		t.Fatalf("a provider switch must drop the old key: %+v %v", got, err)
	}
}

// The key test uses the stored configuration and needs one.
func TestKeyTest(t *testing.T) {
	svc, _, _, _ := newSvc(t, false)
	ctx := context.Background()
	var seen Platform
	svc.SetTester(func(_ context.Context, p Platform) error { seen = p; return nil })
	if err := svc.Test(ctx); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nothing stored: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{Provider: "gemini", Model: "g", APIKey: cst.Strp(apiKey), Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.Test(ctx); err != nil || seen.APIKey != apiKey || seen.Provider != "gemini" {
		t.Fatalf("test: %v %+v", err, seen.Provider)
	}
}

// An OpenAI-compatible server: base URL and model, the key optional. A
// private address needs the audited toggle; loopback and metadata never.
func TestOpenAICompatibleAndPrivateToggle(t *testing.T) {
	svc, repo, audit, _ := newSvc(t, false)
	ctx := context.Background()
	actor := cst.SuperAdmin(t)
	in := Input{Enabled: true, Provider: "openai_compatible", Model: "llama3", BaseURL: "http://10.0.0.5:11434/v1", Reason: "self-hosted model"}

	if _, err := svc.Update(ctx, actor, in, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a private address without the toggle must be refused: %v", err)
	}
	if len(audit.Entries) != 0 {
		t.Fatal("a refused change writes nothing")
	}
	for _, u := range []string{"http://127.0.0.1:11434/v1", "http://localhost:11434/v1", "http://169.254.169.254/v1"} {
		bad := in
		bad.AllowPrivate, bad.BaseURL = true, u
		if _, err := svc.Update(ctx, actor, bad, 0, "", ""); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s must be refused even with the toggle: %v", u, err)
		}
	}
	in.AllowPrivate = true
	got, err := svc.Update(ctx, actor, in, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || !got.AllowPrivate || got.BaseURL != "http://10.0.0.5:11434/v1" || got.KeySet {
		t.Fatalf("got %+v", got)
	}
	base, priv := svc.PlatformAIEndpoint(ctx)
	if base != "http://10.0.0.5:11434/v1" || !priv {
		t.Fatalf("endpoint %s %v", base, priv)
	}
	if _, _, _, ok := svc.PlatformAI(ctx); !ok {
		t.Fatal("a keyless OpenAI-compatible server is usable")
	}
	if len(audit.Entries) != 1 || !strings.Contains(audit.JSON(t), "allow_private") || !strings.Contains(repo.Raw(SettingKey), "allow_private") {
		t.Fatal("the toggle must be recorded in the critical audit row")
	}
	// Switching to a hosted provider drops the base URL and the toggle.
	got, err = svc.Update(ctx, actor, Input{Enabled: true, Provider: "claude", Model: "m", APIKey: cst.Strp(apiKey), Reason: "back to hosted"}, got.Version, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.AllowPrivate || got.BaseURL != "" {
		t.Fatalf("a hosted provider keeps no private toggle: %+v", got)
	}
}

// A model allow-list limits the platform model.
func TestModelAllowList(t *testing.T) {
	svc, _, _, _ := newSvc(t, false)
	ctx := context.Background()
	actor := cst.SuperAdmin(t)
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "not-listed", AllowedModels: []string{"a", "b"}, Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a model outside the list: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "a", AllowedModels: []string{"a", " b ", "a"}, Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if !svc.ModelAllowed(ctx, "b") || svc.ModelAllowed(ctx, "c") {
		t.Fatal("allow-list not applied")
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "a", AllowedModels: []string{"bad model!"}, Reason: "x"}, 1, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad name: %v", err)
	}
}
