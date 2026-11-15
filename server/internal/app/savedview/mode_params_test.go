package savedview

import (
	"errors"
	"net/url"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/savedview"
)

func TestListModeParams(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  string
		err   bool
	}{
		{query: "", want: ""},
		{query: "severity=high", want: ""},
		{query: "mode=query&severity=high", want: "query"},
		{query: "mode=basic", want: "basic"},
		{query: "mode=QUERY", err: true},
		{query: "mode=%3Cscript%3E", err: true},
	} {
		q, _ := url.ParseQuery(tc.query)
		got, err := ListModeParams(q)
		if tc.err {
			if !errors.Is(err, savedview.ErrInvalid) {
				t.Errorf("%q: err = %v, want ErrInvalid", tc.query, err)
			}
			continue
		}
		if err != nil || got[ModeParam] != tc.want || (tc.want == "" && got != nil) {
			t.Errorf("%q: got %v, %v; want mode %q", tc.query, got, err, tc.want)
		}
	}
}

func TestPageParamsNeedAPageThatTakesThem(t *testing.T) {
	if _, err := pageParams(PageConfig{}, nil, map[string]string{"mode": "query"}); !errors.Is(err, savedview.ErrInvalid) {
		t.Errorf("a page without params took one: %v", err)
	}
	got, err := pageParams(PageConfig{Params: ListModeParams}, map[string]string{"kept": "1"}, map[string]string{"mode": "query", "other": "x"})
	if err != nil || got["mode"] != "query" || got["kept"] != "1" || got["other"] != "" {
		t.Errorf("pageParams = %v, %v", got, err)
	}
}
