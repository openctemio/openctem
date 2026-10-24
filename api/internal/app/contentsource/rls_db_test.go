package contentsource_test

import (
	"context"
	"strings"
	"testing"
)

// The shadow-mode read policy on platform rows leaves out hidden sources
// (their address and credential columns), on both tables.
func TestRuleSources_PlatformReadPolicyExcludesHidden_DB(t *testing.T) {
	e := newEnv(t)
	for _, pol := range []string{"content_sources_platform_read", "content_source_snapshots_platform_read"} {
		var expr string
		if err := e.db.QueryRowContext(context.Background(),
			`SELECT pg_get_expr(polqual, polrelid) FROM pg_policy WHERE polname = $1`, pol).Scan(&expr); err != nil {
			t.Fatalf("%s: %v", pol, err)
		}
		if !strings.Contains(expr, "hidden") {
			t.Fatalf("%s does not exclude hidden platform rows: %s", pol, expr)
		}
	}
}
