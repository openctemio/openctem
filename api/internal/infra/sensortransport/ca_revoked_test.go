package sensortransport

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The development CA whose key was published must stay on the list.
func TestLeakedDevCAIsListed(t *testing.T) {
	const leaked = "F6:BD:9D:E7:0E:E4:06:1B:2B:7C:57:E7:F5:24:FA:29:D7:9B:73:23:06:E5:81:BA:44:05:72:E1:D4:3D:83:CD"
	if !isRevokedCA(leaked) {
		t.Fatal("the published development CA fingerprint is not on the revoked list")
	}
}

// A CA on the revoked list is refused from the CA directory and from explicit
// files, with an error that tells the operator how to recover.
func TestLoadCARefusesRevokedCA(t *testing.T) {
	raw, err := newCAPEM(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := parseCA(raw, raw)
	if err != nil {
		t.Fatal(err)
	}
	revokedCAFingerprints[ca.Fingerprint()] = struct{}{}
	t.Cleanup(func() { delete(revokedCAFingerprints, ca.Fingerprint()) })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, caFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadCA("", "", dir)
	if !errors.Is(err, ErrRevokedCA) || !strings.Contains(err.Error(), "delete the CA directory") {
		t.Fatalf("directory CA: want ErrRevokedCA with recovery text, got %v", err)
	}
	pemFile := filepath.Join(dir, caFileName)
	if _, err = LoadCA(pemFile, pemFile, ""); !errors.Is(err, ErrRevokedCA) {
		t.Fatalf("file CA: want ErrRevokedCA, got %v", err)
	}

	// A different CA still loads.
	if _, err = LoadCA("", "", t.TempDir()); err != nil {
		t.Fatalf("a fresh CA must load: %v", err)
	}
}
