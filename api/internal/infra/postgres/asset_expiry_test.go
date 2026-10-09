package postgres

import (
	"strings"
	"testing"
)

func TestBuildExpirySQL(t *testing.T) {
	if got := buildExpirySQL(nil); got != "NULL::timestamptz" {
		t.Errorf("no keys = %q", got)
	}
	one := buildExpirySQL([]string{"not_after"})
	if strings.HasPrefix(one, "COALESCE") || !strings.Contains(one, "pg_input_is_valid((a.properties ->> 'not_after'), 'timestamptz')") {
		t.Errorf("one key = %q", one)
	}
	two := buildExpirySQL([]string{"expires_at", "not_after"})
	if !strings.HasPrefix(two, "COALESCE(") || strings.Count(two, "pg_input_is_valid") != 2 {
		t.Errorf("two keys = %q", two)
	}
	// A key is always a quoted literal, never spliced as SQL.
	if got := buildExpirySQL([]string{"x') OR true --"}); !strings.Contains(got, `'x'') OR true --'`) {
		t.Errorf("quoted key = %q", got)
	}
	if expirySQL == "NULL::timestamptz" {
		t.Error("the registry has no expiry property; certificates and domains should")
	}
}
