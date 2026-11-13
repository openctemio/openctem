package contentpkg

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The catalog types are linked by every binary that reads the content
// catalog (the admin CLI included); the Sigstore client must stay in
// pkg/contentpkg/sigstore so only the server pays for it.
func TestPackageDoesNotLinkSigstoreClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, "github.com/sigstore/") {
			t.Fatalf("pkg/contentpkg links %s; keep the Sigstore client in pkg/contentpkg/sigstore", dep)
		}
	}
}

func TestPublisherVerifierFuncWrapsFailures(t *testing.T) {
	boom := errors.New("boom")
	pv := PublisherVerifierFunc(func(_, _ []byte, id, iss string) (time.Time, error) {
		if id != "who" || iss != "issuer" {
			t.Fatalf("identity %q issuer %q", id, iss)
		}
		return time.Time{}, boom
	})
	_, err := pv.Verify(nil, nil, Publisher{Identity: "who", Issuer: "issuer"})
	if !errors.Is(err, ErrPublisherSignature) || !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}
