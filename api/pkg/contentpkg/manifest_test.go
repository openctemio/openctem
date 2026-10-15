package contentpkg

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func readFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/rules.package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseManifest_Valid(t *testing.T) {
	m, err := ParseManifest(readFixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.ID != "openctem/sast-rules" || m.Namespace() != "openctem" || m.Name() != "sast-rules" {
		t.Fatalf("id: %+v", m)
	}
	if m.Type != TypeRules || !m.Type.IsPack() || m.ContentKind != "semgrep-rules" {
		t.Fatalf("type: %+v", m)
	}
	if !m.License.ServiceUse || m.Permissions.Tier != "T0" || len(m.Dependencies) != 1 {
		t.Fatalf("fields: %+v", m)
	}
	if !strings.Contains(m.Summary, "\n") {
		t.Fatal("a multi-line summary is kept")
	}
}

func TestParseManifest_JSONIsAccepted(t *testing.T) {
	m, err := ParseManifest(readFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	m.Summary = ""
	raw := mustJSON(t, m)
	if _, err := ParseManifest(raw); err != nil {
		t.Fatalf("JSON manifest: %v", err)
	}
}

// mutate returns the fixture with one line replaced (old must exist).
func mutate(t *testing.T, old, repl string) []byte {
	t.Helper()
	s := string(readFixture(t))
	if !strings.Contains(s, old) {
		t.Fatalf("fixture has no %q", old)
	}
	return []byte(strings.Replace(s, old, repl, 1))
}

func TestParseManifest_Refusals(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"unknown field", mutate(t, "type: rules", "type: rules\nextra: 1"), "extra"},
		{"unknown nested field", mutate(t, "  tier: T0", "  tier: T0\n  root: true"), "root"},
		{"wrong apiVersion", mutate(t, "openctem.io/package/v1", "openctem.io/package/v2"), "apiVersion"},
		{"bad id", mutate(t, "id: openctem/sast-rules", "id: OpenCTEM/../x"), "/id"},
		{"id without namespace", mutate(t, "id: openctem/sast-rules", "id: sast-rules"), "/id"},
		{"bad version", mutate(t, "version: 0.1.0", "version: v0.1.0"), "/version"},
		{"build metadata", mutate(t, "version: 0.1.0", "version: 0.1.0+abc"), "/version"},
		{"unknown type", mutate(t, "type: rules", "type: malware"), "/type"},
		{"content kind on a profile", mutate(t, "type: rules", "type: profiles"), "content_kind"},
		{"missing content kind", mutate(t, "content_kind: semgrep-rules\n", ""), "content_kind"},
		{"bad digest", mutate(t, "digest: sha256:4c7a", "digest: sha256:4C7A"), "digest"},
		{"zero size", mutate(t, "size: 173226", "size: 0"), "size"},
		{"oci ref on a file", mutate(t, "  size: 173226", "  size: 173226\n  ref: ghcr.io/openctemio/sensor"), "ref"},
		{"bad range", mutate(t, `">=0.9.0, <2.0.0"`, `"^1.0.0"`), "platform"},
		{"destructive below T2", mutate(t, "side_effects: none", "side_effects: destructive"), "T2"},
		{"declared hosts without the network class", mutate(t, "  network: none", "  network: none\n  declared_hosts: [api.example.com]"), "declared_hosts"},
		{"declared-hosts without hosts", mutate(t, "  network: none", "  network: declared-hosts"), "declared_hosts"},
		{"self dependency", mutate(t, "id: openctem/wordlists-common", "id: openctem/sast-rules"), "dependency"},
		{"no build identity", mutate(t, "  build_identity: https://github.com/openctemio/sast-rules/.github/workflows/release.yml@refs/tags/v0.1.0\n", ""), "build_identity"},
		{"http provenance", mutate(t, "build_issuer: https://", "build_issuer: http://"), "build_issuer"},
		{"control character in title", mutate(t, "title: Official SAST rules", "title: \"Official\\u0007 rules\""), "title"},
		{"bidi override in title", mutate(t, "title: Official SAST rules", "title: \"Official\\u202e rules\""), "title"},
		{"long title", mutate(t, "title: Official SAST rules", "title: "+strings.Repeat("a", 81)), "title"},
		{"anchor", mutate(t, "  tier: T0", "  tier: &t T0"), "anchors"},
		{"float", mutate(t, "size: 173226", "size: 1.5"), "1.5"},
		{"duplicate key", mutate(t, "type: rules", "type: rules\ntype: rules"), "duplicate"},
		{"two documents", append(readFixture(t), []byte("---\nid: x\n")...), "one YAML document"},
		{"empty", nil, "empty"},
		{"too big", []byte(strings.Repeat("#", MaxManifestBytes+1)), "over"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseManifest(c.raw)
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("not ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestValidate_OCIAndFeeds(t *testing.T) {
	base := func() Manifest {
		m, err := ParseManifest(readFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		return *m
	}
	m := base()
	m.Type, m.ContentKind, m.Dependencies = TypeSensors, "", nil
	m.Artifact = Artifact{MediaType: MediaOCIIndex, Digest: m.Artifact.Digest, Size: 1024, Ref: "ghcr.io/openctemio/sensor"}
	m.Compatibility.Protocol = ">=3"
	if err := m.Validate(); err != nil {
		t.Fatalf("sensor: %v", err)
	}
	m.Artifact.Ref = ""
	if err := m.Validate(); err == nil {
		t.Fatal("an OCI artifact needs a ref")
	}
	m.Artifact.Ref = "ghcr.io/openctemio/sensor"
	m.Dependencies = []Dependency{{ID: "openctem/x", Version: ">=1"}}
	if err := m.Validate(); err == nil {
		t.Fatal("an executable cannot have dependencies")
	}

	f := base()
	f.Type, f.ContentKind, f.Dependencies, f.Provenance = TypeFeeds, "", nil, Provenance{}
	f.Artifact = Artifact{MediaType: MediaFeedKeySet, Digest: f.Artifact.Digest, Size: 900}
	if err := f.Validate(); err != nil {
		t.Fatalf("feed: %v", err)
	}
	f.Compatibility.Protocol = ">=3"
	if err := f.Validate(); err == nil {
		t.Fatal("protocol is only for executables")
	}
}

func TestReservedNamespaces(t *testing.T) {
	for _, ns := range []string{"openctem", "openctemio", "official", "platform"} {
		if !IsReservedNamespace(ns) {
			t.Fatalf("%s is reserved", ns)
		}
	}
	if IsReservedNamespace("acme") {
		t.Fatal("acme is not reserved")
	}
}

func TestDigest(t *testing.T) {
	if Digest([]byte("abc")) != "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("digest")
	}
}

func TestSchemaIsServed(t *testing.T) {
	s := SchemaJSON()
	if !strings.Contains(string(s), `"openctem.io/package/v1"`) {
		t.Fatal("schema")
	}
	s[0] = 'x'
	if SchemaJSON()[0] == 'x' {
		t.Fatal("SchemaJSON returns a copy")
	}
}

func FuzzParseManifest(f *testing.F) {
	raw, err := os.ReadFile("testdata/rules.package.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte("a: &x [*x, *x]"))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseManifest(b)
		if err == nil {
			if verr := m.Validate(); verr != nil {
				t.Fatalf("parsed manifest fails Validate: %v", verr)
			}
		}
	})
}
