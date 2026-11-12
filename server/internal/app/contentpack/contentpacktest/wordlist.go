// Package contentpacktest builds packs for tests that go through the whole
// upload path. It is imported by tests only.
package contentpacktest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
)

// WordlistListPath is where WordlistPack puts the list.
const WordlistListPath = "words.txt"

const fixtureCommit = "0123456789abcdef0123456789abcdef01234567"

// WordlistPack returns the files of a platform wordlist pack that passes the
// manifest lint: one web-paths list (list, one entry per line), its manifest
// and its NOTICE. The entries must be valid and unique for web paths.
func WordlistPack(list string) map[string][]byte {
	sum := sha256.Sum256([]byte(list))
	lines := 0
	for _, l := range strings.Split(list, "\n") {
		if l != "" {
			lines++
		}
	}
	manifest := fmt.Sprintf(`version: 1
release: "1"
pack: wordlists-test
class: s
files:
  - path: %s
    purpose: %s
    class: s
    lines: %d
    sha256: %s
    sources:
      - {name: "Test", url: "https://example.org/test", commit: %q, path: "words.txt", spdx: "MIT"}
`, WordlistListPath, contentpack.PurposeWebPaths, lines, hex.EncodeToString(sum[:]), fixtureCommit)
	notice := fixtureCommit + " words.txt MIT\n"
	return map[string][]byte{
		WordlistListPath:                 []byte(list),
		contentpack.WordlistManifestFile: []byte(manifest),
		contentpack.WordlistNoticeFile:   []byte(notice),
	}
}
