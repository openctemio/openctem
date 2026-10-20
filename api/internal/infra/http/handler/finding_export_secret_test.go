package handler

import "testing"

// An export leaves the platform's access control: a secret finding goes out
// without its code lines.
func TestDropSecretSnippets(t *testing.T) {
	secret := FindingResponse{FindingType: "secret", Source: "secret", Snippet: `pw = "REDACTED"`, ContextSnippet: "a\nb", ContextStartLine: 3}
	dropSecretSnippets(&secret)
	if secret.Snippet != "" || secret.ContextSnippet != "" || secret.ContextStartLine != 0 {
		t.Fatalf("secret export kept code lines: %+v", secret)
	}
	bySource := FindingResponse{FindingType: "vulnerability", Source: "secret", Snippet: "x"}
	dropSecretSnippets(&bySource)
	if bySource.Snippet != "" {
		t.Fatal("a finding of the secret source kept its snippet")
	}
	sast := FindingResponse{FindingType: "vulnerability", Source: "sast", Snippet: "x := 1", ContextSnippet: "y"}
	dropSecretSnippets(&sast)
	if sast.Snippet != "x := 1" || sast.ContextSnippet != "y" {
		t.Fatalf("a non-secret finding lost its snippet: %+v", sast)
	}
}
