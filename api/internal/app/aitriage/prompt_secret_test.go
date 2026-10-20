package aitriage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The model provider never gets the code line of a secret finding, however
// well the producer masked it; file and line still go, and other findings keep
// their snippet.
func TestTriagePrompt_NoSnippetForASecretFinding(t *testing.T) {
	s := &AITriageService{promptSanitizer: NewPromptSanitizer()}
	const line = `db_password = "LINE-MARKER-REDACTED"`
	build := func(source vulnerability.FindingSource, ftype vulnerability.FindingType) string {
		f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), source, "tool", vulnerability.SeverityHigh, "msg")
		require.NoError(t, err)
		f.SetFindingType(ftype)
		f.SetLocation("config/app.py", 12, 12, 0, 0)
		f.SetSnippet(line)
		f.SetContextSnippet("before()\n" + line + "\nafter()")
		p, _ := s.buildTriagePromptSafe(f)
		return p
	}
	for name, p := range map[string]string{
		"by type":   build(vulnerability.FindingSourceSAST, vulnerability.FindingTypeSecret),
		"by source": build(vulnerability.FindingSourceSecret, vulnerability.FindingTypeVulnerability),
	} {
		require.NotContains(t, p, "LINE-MARKER", name)
		require.NotContains(t, p, "after()", name)
		require.True(t, strings.Contains(p, "config/app.py"), name+": the file stays")
	}
	require.Contains(t, build(vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability), "LINE-MARKER", "other findings keep their snippet")
}
