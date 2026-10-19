package unit

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

// composeService is the part of a Compose service these checks read.
type composeService struct {
	Command    yaml.Node `yaml:"command"`
	Entrypoint yaml.Node `yaml:"entrypoint"`
	Logging    yaml.Node `yaml:"logging"`
}

func loadCompose(t *testing.T, path string) map[string]composeService {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Services map[string]composeService `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return f.Services
}

// nodeText returns every scalar under n.
func nodeText(n *yaml.Node) []string {
	if n.Kind == yaml.ScalarNode {
		return []string{n.Value}
	}
	var out []string
	for _, c := range n.Content {
		out = append(out, nodeText(c)...)
	}
	return out
}

// A password interpolated by Compose into a command line is readable by every
// host user while the process runs (ps, /proc/<pid>/cmdline) and stays in the
// container's Cmd for good. Passwords reach containers through the
// environment (PGPASSWORD and the like). "$${...}" is escaped: the container's
// shell expands it, so the value is not on the container's command line.
func TestDeployComposeKeepsPasswordsOffTheCommandLine(t *testing.T) {
	interpolated := regexp.MustCompile(`(^|[^$])\$\{?[A-Z0-9_]*(PASSWORD|SECRET)`)
	files, err := filepath.Glob("../../deploy/docker-compose*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no compose files found (%v)", err)
	}
	for _, f := range files {
		for name, svc := range loadCompose(t, f) {
			for _, part := range []*yaml.Node{&svc.Command, &svc.Entrypoint} {
				for _, s := range nodeText(part) {
					if interpolated.MatchString(s) {
						t.Errorf("%s: service %s puts a secret on the command line: %q", filepath.Base(f), name, s)
					}
				}
			}
		}
	}
}

// bootstrap-admin prints one-time credentials: its output must not be kept
// in a container log on the host.
func TestDeployComposeBootstrapAdminHasNoLog(t *testing.T) {
	svc, ok := loadCompose(t, "../../deploy/docker-compose.yml")["bootstrap-admin"]
	if !ok {
		t.Fatal("bootstrap-admin service not found")
	}
	var logging struct {
		Driver string `yaml:"driver"`
	}
	if err := svc.Logging.Decode(&logging); err != nil || logging.Driver != "none" {
		t.Fatalf("bootstrap-admin logging driver = %q (%v), want none", logging.Driver, err)
	}
}
