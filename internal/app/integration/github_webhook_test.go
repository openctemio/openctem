package integration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func ghSign(body []byte, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestVerifyGitHubSignature(t *testing.T) {
	body := []byte(`{"ref":"refs/heads/main"}`)
	secret := "s3cr3t"

	if !VerifyGitHubSignature(body, ghSign(body, secret), secret) {
		t.Error("valid signature should verify")
	}
	if VerifyGitHubSignature(body, ghSign(body, "wrong"), secret) {
		t.Error("signature under a different secret must not verify")
	}
	if VerifyGitHubSignature(body, ghSign([]byte("tampered"), secret), secret) {
		t.Error("signature over a different body must not verify")
	}
	if VerifyGitHubSignature(body, ghSign(body, secret), "") {
		t.Error("empty secret must not verify")
	}
	if VerifyGitHubSignature(body, "deadbeef", secret) {
		t.Error("missing sha256= prefix must not verify")
	}
	if VerifyGitHubSignature(body, "sha256=nothex!!", secret) {
		t.Error("non-hex signature must not verify")
	}
}

func TestParseGitHubPush(t *testing.T) {
	body := []byte(`{"ref":"refs/heads/feature/x","after":"abc123","repository":{"full_name":"acme/widgets"}}`)
	ev, err := ParseGitHubPush(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Branch != "feature/x" || ev.After != "abc123" || ev.RepoFullName != "acme/widgets" {
		t.Errorf("unexpected parse: %+v", ev)
	}
	if ev.Deleted {
		t.Error("non-zero after must not be a deletion")
	}

	// Branch deletion (zero SHA).
	del, err := ParseGitHubPush([]byte(`{"ref":"refs/heads/old","after":"0000000000000000000000000000000000000000","repository":{"full_name":"acme/widgets"}}`))
	if err != nil {
		t.Fatalf("parse del: %v", err)
	}
	if !del.Deleted {
		t.Error("zero after SHA should be flagged as a deletion")
	}

	if _, err := ParseGitHubPush([]byte(`not json`)); err == nil {
		t.Error("invalid JSON should error")
	}
}
