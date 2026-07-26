package ingest

import "testing"

// A finding location whose lowercase form is LONGER than the original used to
// panic: the offset was found in strings.ToLower(path) but indexed into path.
// "Ⱥ" (U+023A) is 2 bytes and lowercases to "ⱥ" (U+2C65) at 3 bytes, so two of
// them shift every later offset by 2 — enough to index past the end. Any
// authenticated agent could send this in a CTIS finding and kill the process.
func TestSanitizePathForProperty_NonLengthPreservingLowercase(t *testing.T) {
	cases := []string{
		"ȺȺ/home/x/a.go",
		"Ⱥ/home/user/project/src/main.go",
		"ȺȺȺȺȺȺȺȺ/root/deep/nested/file.go",
		"Ⱥ" + "C:\\Users\\bob\\proj\\a.cs",
	}
	for _, in := range cases {
		// The contract is only "must not panic and must return something usable";
		// the exact redaction for these exotic inputs is not load-bearing.
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("sanitizePathForProperty(%q) panicked: %v", in, rec)
				}
			}()
			_ = sanitizePathForProperty(in)
		}()
	}
}

// The normal, ASCII case must keep behaving as before: a home-dir path is
// redacted down to the project-relative portion.
func TestSanitizePathForProperty_RedactsHomePrefix(t *testing.T) {
	got := sanitizePathForProperty("/home/alice/work/project/src/main.go")
	if got == "" {
		t.Fatal("expected a non-empty sanitized path")
	}
	if got == "/home/alice/work/project/src/main.go" {
		t.Errorf("home prefix was not redacted: %q", got)
	}
	// Case-insensitive matching must still work (the lengths match here).
	if up := sanitizePathForProperty("/HOME/alice/work/project/src/main.go"); up == "/HOME/alice/work/project/src/main.go" {
		t.Errorf("uppercase home prefix was not redacted: %q", up)
	}
}
