package scannertemplate

import "testing"

// TestVerifySignature covers the constant-time signature check: a matching
// HMAC verifies, a wrong/empty one does not. (The comparison moved from a
// byte-wise == to hmac.Equal to close a timing-oracle on the HMAC value.)
func TestVerifySignature(t *testing.T) {
	const secret = "s3cr3t-signing-key"
	content := []byte("id: test\ninfo:\n  name: demo\n")

	tmpl := &ScannerTemplate{Content: content}
	tmpl.SetSignature(ComputeSignature(content, secret))

	t.Run("valid signature verifies", func(t *testing.T) {
		if !tmpl.VerifySignature(secret) {
			t.Fatal("expected valid signature to verify")
		}
	})

	t.Run("wrong secret fails", func(t *testing.T) {
		if tmpl.VerifySignature("wrong-key") {
			t.Fatal("expected verification to fail with the wrong secret")
		}
	})

	t.Run("tampered content fails", func(t *testing.T) {
		tampered := &ScannerTemplate{Content: []byte("id: evil\n")}
		tampered.SetSignature(tmpl.SignatureHash) // signature of the original content
		if tampered.VerifySignature(secret) {
			t.Fatal("expected verification to fail when content no longer matches the signature")
		}
	})

	t.Run("empty signature fails", func(t *testing.T) {
		empty := &ScannerTemplate{Content: content}
		if empty.VerifySignature(secret) {
			t.Fatal("expected verification to fail when no signature is set")
		}
	})
}
