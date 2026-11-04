package vulncatalog

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Golden ids: computed once by the database functions of the migration
// vuln_catalog_deterministic_keys (uuid-ossp uuid_generate_v5), an
// implementation independent of this package. They never change: a change
// here changes the id of every global product or version in every cell.
func TestDeterministicKeys_Golden(t *testing.T) {
	if NSProduct.String() != "d0cdc07f-60f4-4ede-bd53-0791837a5d49" || NSVersion.String() != "4217cc2b-7a83-41b5-9bce-0806b01c2b2e" {
		t.Fatal("a key namespace changed: every deterministic id would change")
	}
	pid := shared.MustIDFromString("6f1c1e9e-6a55-5f55-9f0e-0123456789ab")
	cases := []struct {
		name string
		got  shared.ID
		want string
	}{
		{"cpe product", ProductID(ProductKeyCPE("a", "f5", "nginx")), "24d30442-d7b4-5369-93c8-dfc503ca128e"},
		{"purl product", ProductID(ProductKeyPurl("npm", "", "lodash")), "12b53d48-7083-58af-bbae-4a2d94572075"},
		{"colon in vendor", ProductID(ProductKeyCPE("a", "a:b", "c")), "8b51f65c-80dc-559d-9e9d-c373da4ba246"},
		{"colon in product", ProductID(ProductKeyCPE("a", "a", "b:c")), "7e1215d0-f550-5b8a-be7e-16319513edfc"},
		{"normalised version", VersionID(pid, "semver", "1.2.3", "1.2.3", "", ""), "623ec48e-6025-5493-9e94-67aa5ae5f340"},
		{"raw version", VersionID(pid, "generic", "", "build 7", "", ""), "a4fad362-b8a0-56c6-b60d-a3558fc3b326"},
	}
	for _, c := range cases {
		if c.got.String() != c.want {
			t.Errorf("%s: id = %s, want %s", c.name, c.got, c.want)
		}
	}
}

// Separators inside a part are escaped, so different tuples never share a key.
func TestProductKey_Escaping(t *testing.T) {
	if got := ProductKeyCPE("a", `x\:y`, "z/w"); got != `cpe:a:x\\\:y:z\/w` {
		t.Fatalf("key = %q", got)
	}
	if ProductKeyCPE("a", "a:b", "c") == ProductKeyCPE("a", "a", "b:c") {
		t.Fatal("colon split collides")
	}
	if ProductKeyPurl("golang", "github.com/x", "y") == ProductKeyPurl("golang", "github.com", "x/y") {
		t.Fatal("slash split collides")
	}
	if ProductKeyCPE("a", "npm", "x") == ProductKeyPurl("npm", "", "x") {
		t.Fatal("cpe and purl keys collide")
	}
}

// A version that does not normalise is identified by its raw string, and two
// raw strings never share an id with a normalised one.
func TestVersionID_RawIdentity(t *testing.T) {
	pid := shared.NewID()
	if VersionID(pid, "generic", "", "1.0", "", "") == VersionID(pid, "generic", "1.0", "1.0", "", "") {
		t.Fatal("raw and normalised identities collide")
	}
	if VersionID(pid, "generic", "1.0", "x", "", "") != VersionID(pid, "generic", "1.0", "y", "", "") {
		t.Fatal("the raw string is not part of a normalised identity")
	}
	if VersionID(pid, "semver", "1.0", "", "", "") == VersionID(shared.NewID(), "semver", "1.0", "", "", "") {
		t.Fatal("versions of different products collide")
	}
}
