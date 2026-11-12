package scan

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Refused: credentials beyond doubt. Warned only: values that merely look
// random, and mode words under credential-named keys.
func TestRefusedConfigSecrets(t *testing.T) {
	refused := map[string]any{
		"headers":      map[string]any{"Authorization": "Bearer abcdefgh12345678"},
		"password":     "hunter22",
		"api_key":      "k-0123456789",
		"proxy":        "http://bob:pw123456@10.0.0.1:3128",
		"github_token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB",
	}
	got := RefusedConfigSecrets(refused)
	if len(got) != len(refused) {
		t.Fatalf("refused %v", got)
	}
	warnedOnly := map[string]any{
		"auth":        "basic",
		"auth_scheme": "bearer",
		"token":       "none",
		"bucket":      "prod-Assets-2024-eu-west-Q9x7",
		"api_key":     "${SHODAN_KEY}",
		"severity":    "critical",
	}
	if got := RefusedConfigSecrets(warnedOnly); len(got) != 0 {
		t.Fatalf("refused a non-credential: %v", got)
	}
	if len(DetectConfigSecrets(map[string]any{"bucket": "prod-Assets-2024-eu-west-Q9x7"})) == 0 {
		t.Fatal("a high-entropy value is no longer warned about")
	}
	err := RefuseConfigSecrets(map[string]any{"password": "hunter22", "ok": "x"})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodeScannerConfigSecret || !errors.Is(err, shared.ErrValidation) ||
		!strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "hunter22") {
		t.Fatalf("refusal: %v", err)
	}
	if RefuseConfigSecrets(map[string]any{"severity": "high"}) != nil {
		t.Fatal("clean config refused")
	}
}

// SECURITY: a credential nested past the scan depth is refused, not skipped.
func TestRefusedConfigSecretsRefusesTooDeep(t *testing.T) {
	var deep any = map[string]any{"password": "hunter2hunter2"}
	for range maxSecretScanDepth + 4 {
		deep = map[string]any{"n": deep}
	}
	got := RefusedConfigSecrets(map[string]any{"root": deep})
	if len(got) == 0 || got[0].Reason != SecretReasonTooDeep {
		t.Fatalf("deep nesting not refused: %v", got)
	}
	if RefuseConfigSecrets(map[string]any{"root": deep}) == nil {
		t.Fatal("RefuseConfigSecrets accepted deep nesting")
	}
	var list any = []any{"x"}
	for range maxSecretScanDepth + 4 {
		list = []any{list}
	}
	if len(RefusedConfigSecrets(map[string]any{"l": list})) == 0 {
		t.Fatal("deep list accepted")
	}
}

// SECURITY: only an explicit mode word is exempt under a credential key; a
// short lower-case secret is refused. A path value is exempt only under a
// file or path key.
func TestRefusedConfigSecretsModeWordsAndPaths(t *testing.T) {
	for _, w := range []string{"basic", "Bearer", "digest", "none", "oauth2", "apikey", "header", "query", "cookie", "form"} {
		if got := RefusedConfigSecrets(map[string]any{"auth": w}); len(got) != 0 {
			t.Errorf("mode word %q refused: %v", w, got)
		}
	}
	for _, v := range []string{"hunter", "letmein", "password", "swordfish-x"} {
		if got := RefusedConfigSecrets(map[string]any{"password": v}); len(got) != 1 {
			t.Errorf("short secret %q not refused", v)
		}
	}
	for _, k := range []string{"token_file", "key_path", "file", "path", "tokenFile"} {
		if got := RefusedConfigSecrets(map[string]any{k: "/etc/secrets/t"}); len(got) != 0 {
			t.Errorf("path under %q refused: %v", k, got)
		}
	}
	for _, k := range []string{"token", "password", "api_key"} {
		if got := RefusedConfigSecrets(map[string]any{k: "/s3cr3tvalue"}); len(got) != 1 {
			t.Errorf("slash-led secret under %q not refused", k)
		}
	}
}
