package scan

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
