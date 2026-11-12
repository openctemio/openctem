package query

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/querylang"
)

type valuesExec struct {
	err   error
	calls int
}

func (f *valuesExec) Explain(context.Context, *querylang.Plan) (querylang.Estimate, error) {
	return querylang.Estimate{}, nil
}

func (f *valuesExec) Run(_ context.Context, p *querylang.Plan) (*querylang.Result, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &querylang.Result{Columns: p.Columns, Rows: [][]any{{"critical", int64(4)}, {"high", int64(2)}}}, nil
}

func adminCaller(user string) Caller {
	return Caller{TenantID: "11111111-1111-1111-1111-111111111111", UserID: user, IsAdmin: true}
}

func TestValues_TimeoutListsEnumWithoutCounts(t *testing.T) {
	s := NewService(&valuesExec{err: querylang.ErrTimeout}, nil, nil)
	res, err := s.Values(context.Background(), adminCaller("22222222-2222-2222-2222-222222222222"), ValuesInput{Entity: "findings", Field: "severity", Prefix: "c"})
	if err != nil || res.Counted || len(res.Values) != 1 || res.Values[0].Value != "critical" || res.Values[0].Count != nil {
		t.Fatalf("timeout = %+v, %v", res, err)
	}
}

func TestValues_CachePerCaller(t *testing.T) {
	ex := &valuesExec{}
	s := NewService(ex, nil, nil)
	now := time.Now()
	s.values.now = func() time.Time { return now }
	in := ValuesInput{Entity: "findings", Field: "severity"}
	u1, u2 := adminCaller("22222222-2222-2222-2222-222222222222"), adminCaller("33333333-3333-3333-3333-333333333333")
	for range 2 {
		if _, err := s.Values(context.Background(), u1, in); err != nil {
			t.Fatal(err)
		}
	}
	if ex.calls != 1 {
		t.Fatalf("same caller twice ran %d queries", ex.calls)
	}
	if _, err := s.Values(context.Background(), u2, in); err != nil || ex.calls != 2 {
		t.Fatalf("another user was served the cache (%d runs, %v)", ex.calls, err)
	}
	now = now.Add(valuesCacheTTL + time.Second)
	if _, _ = s.Values(context.Background(), u1, in); ex.calls != 3 {
		t.Fatalf("an expired answer was served (%d runs)", ex.calls)
	}
	// Fields that cannot be grouped, unknown or not, are one answer.
	for _, f := range []string{"description", "nope", "text_search", "program_asset"} {
		if _, err := s.Values(context.Background(), u1, ValuesInput{Entity: "findings", Field: f}); err != ErrUnknownField { //nolint:errorlint // the sentinel itself
			t.Errorf("%s: %v", f, err)
		}
	}
}
