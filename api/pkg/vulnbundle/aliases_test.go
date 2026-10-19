package vulnbundle

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func gzLines(t *testing.T, lines ...string) ([]byte, *AliasManifest) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(strings.Join(lines, "\n") + "\n"))
	_ = zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), &AliasManifest{Files: []File{{Name: AliasesEntriesFile, SHA256: hex.EncodeToString(sum[:]), Size: int64(buf.Len()), Records: len(lines)}, {Name: AliasesStateFile}}}
}

func TestParseAliasEntries(t *testing.T) {
	ok := `{"kind":"cpe","value":"a:google_inc:chrome","target":"a:google:chrome","basis":"learned","support":3}`
	gz, m := gzLines(t, ok)
	got, err := ParseAliasEntries(gz, m)
	if err != nil || len(got) != 1 || got[0].Value != "a:google_inc:chrome" || got[0].Target != "a:google:chrome" || got[0].Basis != "learned" {
		t.Fatalf("%v %v", got, err)
	}
	bad := []struct {
		name  string
		lines []string
		mut   func(*AliasManifest)
	}{
		{"unknown field", []string{`{"kind":"cpe","value":"a:x:y","target":"a:z:y","basis":"","support":0,"extra":1}`}, nil},
		{"trailing data", []string{ok + ` {}`}, nil},
		{"more than stated", []string{ok, ok}, func(m *AliasManifest) { m.Files[0].Records = 1 }},
		{"fewer than stated", []string{ok}, func(m *AliasManifest) { m.Files[0].Records = 2 }},
		{"hash mismatch", []string{ok}, func(m *AliasManifest) { m.Files[0].SHA256 = strings.Repeat("0", 64) }},
		{"oversized line", []string{`{"kind":"` + strings.Repeat("x", MaxRecordBytes+1) + `"}`}, nil},
	}
	for _, c := range bad {
		gz, m := gzLines(t, c.lines...)
		if c.mut != nil {
			c.mut(m)
		}
		if _, err := ParseAliasEntries(gz, m); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
