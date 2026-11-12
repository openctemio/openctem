package postgres

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// The SQL exploitation signal uses the domain EPSS threshold.
func TestExploitSignalClauseUsesDomainThreshold(t *testing.T) {
	want := fmt.Sprintf(">= %g", asset.ExploitEPSSThreshold)
	if !strings.Contains(exploitSignalClause, want) {
		t.Fatalf("exploitSignalClause = %s, want it to contain %q", exploitSignalClause, want)
	}
}
