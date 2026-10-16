package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// signingScript runs scripts/signing/<name> in a temp dir with a prebuilt
// content-bundle and returns stdout and stderr together.
func signingScript(t *testing.T, bin, name string, args ...string) (string, error) {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("..", "..", "..", "scripts", "signing", name))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...) // #nosec G204 -- test runs the repo's own script
	cmd.Env = append(os.Environ(), "CONTENT_BUNDLE_BIN="+bin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return out.String(), err
}

func keySetVersion(t *testing.T, path string) float64 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env struct{ Payload string }
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var ks map[string]any
	if err := json.Unmarshal(payload, &ks); err != nil {
		t.Fatal(err)
	}
	return ks["version"].(float64)
}

// init-keys.sh creates the keys with private modes, prints only public
// material (no seed anywhere in its output), refuses to overwrite, and
// rotate-keyset.sh re-signs with the next version.
func TestSigningScripts(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	bin := filepath.Join(t.TempDir(), "content-bundle")
	build := exec.Command("go", "build", "-o", bin, ".") // #nosec G204 -- fixed arguments
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir := filepath.Join(t.TempDir(), "keys")

	out, err := signingScript(t, bin, "init-keys.sh", dir)
	if err != nil {
		t.Fatalf("init-keys: %v\n%s", err, out)
	}
	var seeds []string
	for _, f := range []string{"catalog-root.key", "online.key"} {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		seed := strings.TrimSpace(string(raw))
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(seed) {
			t.Fatalf("%s is not a hex seed", f)
		}
		seeds = append(seeds, seed)
		if st, _ := os.Stat(filepath.Join(dir, f)); st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, st.Mode().Perm())
		}
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v", st.Mode().Perm())
	}
	pub, _ := os.ReadFile(filepath.Join(dir, "online.pub"))
	for _, want := range []string{"keyset.dsse.json", "--env release-feed", "< \"" + filepath.Join(dir, "online.key") + "\"", strings.TrimSpace(string(pub)), "SHA256:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if v := keySetVersion(t, filepath.Join(dir, "keyset.dsse.json")); v != 1 {
		t.Fatalf("key set version %v", v)
	}

	// Existing keys are never overwritten, and the refusal prints no secret.
	before, _ := os.ReadFile(filepath.Join(dir, "online.key"))
	out2, err := signingScript(t, bin, "init-keys.sh", dir)
	if err == nil {
		t.Fatal("init-keys overwrote existing keys")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "online.key"))
	if !bytes.Equal(before, after) {
		t.Fatal("the online key changed")
	}

	out3, err := signingScript(t, bin, "rotate-keyset.sh", dir)
	if err != nil {
		t.Fatalf("rotate-keyset: %v\n%s", err, out3)
	}
	if v := keySetVersion(t, filepath.Join(dir, "keyset.dsse.json")); v != 2 {
		t.Fatalf("key set version after rotation %v", v)
	}
	if v := keySetVersion(t, filepath.Join(dir, "keyset.dsse.json.prev")); v != 1 {
		t.Fatalf("previous key set version %v", v)
	}
	for _, o := range []string{out, out2, out3} {
		for _, s := range seeds {
			if strings.Contains(o, s) {
				t.Fatal("a script printed private key bytes")
			}
		}
	}
	if _, err := signingScript(t, bin, "rotate-keyset.sh", filepath.Join(t.TempDir(), "nothing")); err == nil {
		t.Fatal("rotate-keyset ran without a root key")
	}
}
