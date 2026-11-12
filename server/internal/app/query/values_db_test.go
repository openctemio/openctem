package query_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/query"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Value completion counts only what the caller can list: their tenant,
// their data scope, the pentest member rule and the mandatory exclusions.
func TestValues_ScopedCounts_DB(t *testing.T) {
	e := newQEnv(t)
	ctx := context.Background()
	counts := func(c query.Caller, field, prefix, filter string) map[string]int64 {
		t.Helper()
		res, err := e.svc.Values(ctx, c, query.ValuesInput{Entity: "findings", Field: field, Prefix: prefix, Filter: filter})
		if err != nil {
			t.Fatalf("values %s %q: %v", field, filter, err)
		}
		if !res.Counted {
			t.Fatalf("values %s: not counted", field)
		}
		out := map[string]int64{}
		for _, v := range res.Values {
			out[fmt.Sprint(v.Value)] = *v.Count
		}
		return out
	}
	eq := func(name string, got, want map[string]int64) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	// memberA: A1 critical + high, D1 low (B1, the pentest finding, the
	// draft, the program asset and the branch-only finding are not theirs).
	eq("member severities", counts(e.caller(e.memberA, false), "severity", "", ""), map[string]int64{"critical": 1, "high": 1, "low": 1})
	// The admin: the tenant, still without drafts, program or branch-only.
	eq("admin severities", counts(e.caller(e.own, true), "severity", "", ""), map[string]int64{"critical": 3, "high": 1, "low": 1})
	// Tenant B's owner sees tenant B only.
	eq("other tenant", counts(e.caller(e.ownerB, true), "severity", "", ""), map[string]int64{"critical": 1})
	// The field's own condition is left out; other conditions apply.
	eq("own field ignored", counts(e.caller(e.memberA, false), "severity", "", "severity=critical"), map[string]int64{"critical": 1, "high": 1, "low": 1})
	eq("other filter applied", counts(e.caller(e.memberA, false), "severity", "", "cvss>=7"), map[string]int64{"critical": 1, "high": 1})
	eq("short name and prefix", counts(e.caller(e.own, true), "tool", "q-", ""), map[string]int64{"q-tool": 5})
	eq("prefix narrows", counts(e.caller(e.own, true), "severity", "cr", ""), map[string]int64{"critical": 3})
	// Asset attributes need assets:read; without it the field is unknown,
	// exactly like a field that does not exist.
	findingsOnly := e.caller(e.memberA, false, "findings:read")
	for _, f := range []string{"asset.type", "nonsense"} {
		if _, err := e.svc.Values(ctx, findingsOnly, query.ValuesInput{Entity: "findings", Field: f}); !errors.Is(err, query.ErrUnknownField) {
			t.Errorf("%s without assets:read: %v", f, err)
		}
	}
	if _, err := e.svc.Values(ctx, e.caller(e.memberA, false, "assets:read"), query.ValuesInput{Entity: "findings", Field: "severity"}); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("without findings:read: %v", err)
	}
	// A member with no scope rows counts nothing.
	eq("no scope", counts(e.caller(e.noScope, false), "severity", "", ""), map[string]int64{})
}
