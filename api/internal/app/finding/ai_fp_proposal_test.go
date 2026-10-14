package finding

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestAIProposalJustification_BoundedAndClean(t *testing.T) {
	j := aiProposalJustification(0.934, "line1\nline2\x00\x1b[31m red")
	require.True(t, strings.HasPrefix(j, "AI triage (false-positive likelihood 0.93): "))
	require.NotContains(t, j, "\n")
	require.NotContains(t, j, "\x00")
	require.NotContains(t, j, "\x1b")

	long := aiProposalJustification(0.99, strings.Repeat("é", 2000))
	require.LessOrEqual(t, len(long), vulnerability.MaxActorJustificationLength)
	require.True(t, utf8.ValidString(long))
	require.True(t, strings.HasSuffix(long, "..."))

	require.Contains(t, aiProposalJustification(0.9, "  "), "no rationale given")
}
