package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func descriptorContract(raw string) *ToolContract {
	sum := sha256.Sum256([]byte(raw))
	return &ToolContract{APIVersion: ToolContractAPIVersion, Digest: "sha256:" + hex.EncodeToString(sum[:]),
		Version: "2.0.0", Class: "target-scan", Tier: "T1", Produces: []string{"asset:open_port"},
		Implements: []string{"scan.ports@1"}}
}

const goodDescriptor = `{"apiVersion":"openctem.io/tool/v1","name":"acme-ports","version":"2.0.0","presentation":{"display_name":"Acme"}}`

func TestSanitizeToolDescriptor(t *testing.T) {
	c := descriptorContract(goodDescriptor)
	got, why := SanitizeToolDescriptor(c, json.RawMessage(goodDescriptor))
	if string(got) != goodDescriptor || why != "" {
		t.Fatalf("kept %s (%s)", got, why)
	}
	if d, why := SanitizeToolDescriptor(c, nil); d != nil || why != "" {
		t.Fatal("no descriptor is not an error")
	}

	cases := map[string]struct {
		raw  string
		c    *ToolContract
		want string
	}{
		// SECURITY: a descriptor that is not the one the digest names is
		// refused, so a sensor cannot show one contract and enforce another.
		"another document": {`{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","name":"x"}`, c, "does not hash"},
		"not an object":    {`["a"]`, descriptorContract(`["a"]`), "not a JSON object"},
		"not JSON":         {`{`, descriptorContract(`{`), "not JSON"},
		"version mismatch": {`{"apiVersion":"openctem.io/tool/v1","version":"9.0.0"}`, descriptorContract(`{"apiVersion":"openctem.io/tool/v1","version":"9.0.0"}`), "does not match"},
		"control char":     {`{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","description":"a\u0007b"}`, descriptorContract(`{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","description":"a\u0007b"}`), "control character"},
		"bidi override":    {`{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","n":"\u202eexe"}`, descriptorContract(`{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","n":"\u202eexe"}`), "control character"},
		"control in key":   {`{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","a\nb":1}`, descriptorContract(`{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","a\nb":1}`), "control character"},
	}
	// Version from the contract: the hash matches but the version differs.
	cases["version mismatch"].c.Version = "2.0.0"
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, why := SanitizeToolDescriptor(tc.c, json.RawMessage(tc.raw))
			if got != nil || !strings.Contains(why, tc.want) {
				t.Fatalf("kept %s, reason %q, want %q", got, why, tc.want)
			}
		})
	}

	big := `{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","d":"` + strings.Repeat("a", MaxToolDescriptorBytes) + `"}`
	if got, why := SanitizeToolDescriptor(descriptorContract(big), json.RawMessage(big)); got != nil || !strings.Contains(why, "too large") {
		t.Fatalf("oversized descriptor: %q", why)
	}

	deep := strings.Repeat(`{"a":`, 40) + `"x"` + strings.Repeat(`}`, 40)
	deep = `{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","n":` + deep + `}`
	if got, _ := SanitizeToolDescriptor(descriptorContract(deep), json.RawMessage(deep)); got != nil {
		t.Fatal("a descriptor deeper than the walk bound is kept")
	}
}

// The manifest keeps a valid descriptor and records why an invalid one was
// dropped, keeping the contract.
func TestManifestKeepsTheDescriptor(t *testing.T) {
	good := descriptorContract(goodDescriptor)
	good.Descriptor = json.RawMessage(goodDescriptor)
	bad := descriptorContract(goodDescriptor)
	bad.Descriptor = json.RawMessage(`{"apiVersion":"openctem.io/tool/v1","version":"2.0.0","name":"swapped"}`)
	m := Manifest{Schema: ManifestSchema, Tools: []ManifestTool{
		{Name: "good", Installed: true, Contract: good},
		{Name: "bad", Installed: true, Contract: bad},
	}}
	out, ignored := m.Sanitized(m.CapabilityInput().Sanitize(map[string]bool{"good": true, "bad": true}, nil), time.Now())
	if string(out.ToolDescriptor("good")) != goodDescriptor {
		t.Fatalf("good descriptor: %s", out.ToolDescriptor("good"))
	}
	if out.ToolContract("bad") == nil || out.ToolDescriptor("bad") != nil {
		t.Fatal("an invalid descriptor drops itself, not the contract")
	}
	found := false
	for _, ig := range ignored {
		if ig.Reason == IgnoredInvalidDescriptor && strings.HasSuffix(ig.Path, ".contract.descriptor") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ignored = %+v", ignored)
	}
	if (Manifest{}).ToolDescriptor("none") != nil {
		t.Fatal("unknown tool")
	}
}
