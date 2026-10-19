package bootstrapadmin

import (
	"bytes"
	"strings"
	"testing"
)

// Without a terminal on stdout (a pipe, a file, a container log) the command
// prints no one-time credential: it refuses before it touches the database.
func TestNoSecretsWithoutTerminal(t *testing.T) {
	env := map[string]string{"DATABASE_URL": "postgres://u@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"}
	getEnv := func(k string) string { return env[k] }
	args := []string{"-email=admin@example.com", "-backup-email=bg@example.com"}

	var stdout, stderr bytes.Buffer
	code := runBootstrap(args, getEnv, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatal("ran without a terminal and without -print-secrets")
	}
	if stdout.Len() != 0 {
		t.Fatalf("printed to a non-terminal stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "-print-secrets") || strings.Contains(stderr.String(), "pinging") {
		t.Fatalf("want the refusal before any database access, got %q", stderr.String())
	}

	// -print-secrets opts in: the run goes on to the database (unreachable here).
	stdout.Reset()
	stderr.Reset()
	code = runBootstrap(append(args, "-print-secrets"), getEnv, strings.NewReader(""), &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "database") {
		t.Fatalf("with -print-secrets: code %d, stderr %q", code, stderr.String())
	}
}

func TestCommandActor(t *testing.T) {
	env := map[string]string{"SUDO_USER": "alice", "USER": "root"}
	if a := commandActor(func(k string) string { return env[k] }); a.OSUser != "alice" || a.Hostname == "" {
		t.Fatalf("sudo: %+v", a)
	}
	delete(env, "SUDO_USER")
	if a := commandActor(func(k string) string { return env[k] }); a.OSUser != "root" {
		t.Fatalf("user: %+v", a)
	}
}

func TestTypedConfirmation(t *testing.T) {
	var prompt bytes.Buffer
	confirm := typedConfirmation(strings.NewReader("Admin@Example.com\nwrong@example.com\n"), &prompt)
	if !confirm("admin@example.com") {
		t.Fatal("matching email (any case) refused")
	}
	if confirm("admin@example.com") {
		t.Fatal("different email accepted")
	}
	if confirm("admin@example.com") {
		t.Fatal("end of input accepted")
	}
	if !strings.Contains(prompt.String(), "Type admin@example.com") {
		t.Fatalf("prompt: %q", prompt.String())
	}
}
