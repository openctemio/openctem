package logger

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// The CodeQL query .github/codeql/go-queries/LogInjectionUnstructured.ql
// treats the key-value attributes of a log/slog call as safe because the
// handlers New builds escape them. These tests pin that: an attribute value
// carrying CR/LF and a forged record stays inside one output line, in both
// formats, through the sampling and counting wrappers.
func TestAttributesCannotForgeLogLines(t *testing.T) {
	forged := "x\nlevel=ERROR msg=\"forged\" admin=true\r\n{\"level\":\"ERROR\",\"msg\":\"forged\"}"
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			l := New(Config{Level: "info", Format: format, Output: &buf})
			l.Info("probe", "value", forged, "err", errors.New(forged), slog.String("attr", forged))
			l.With("bound", forged).Warn("probe2")
			l.WithGroup("g\nh").Error("probe3", "k", forged)

			out := strings.TrimRight(buf.String(), "\n")
			lines := strings.Split(out, "\n")
			if len(lines) != 3 {
				t.Fatalf("want 3 lines (one per record), got %d:\n%s", len(lines), out)
			}
			for _, line := range lines {
				if strings.ContainsRune(line, '\r') {
					t.Fatalf("raw CR in a %s line: %q", format, line)
				}
			}
		})
	}
}
