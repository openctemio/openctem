package savedview

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/savedview"
)

func TestServicePage_RegistryDecidesKeyAndPermission(t *testing.T) {
	s := NewService(nil, map[string]PageConfig{savedview.PageFindings: {Permission: permission.FindingsRead.String()}}, nil)
	has := func(perms ...string) Caller {
		return Caller{Has: func(p string) bool {
			for _, q := range perms {
				if q == p {
					return true
				}
			}
			return false
		}}
	}
	for _, p := range savedview.Pages() {
		if _, err := s.page(has(p.Permission.String()), p.Key); err != nil {
			t.Errorf("%s with %q: %v", p.Key, p.Permission, err)
		}
		_, err := s.page(has("some:other"), p.Key)
		_, errNil := s.page(Caller{}, p.Key)
		var forbidden *PageForbiddenError
		if !errors.Is(err, savedview.ErrPageForbidden) || !errors.As(err, &forbidden) || forbidden.Permission != p.Permission.String() {
			t.Errorf("%s without %q: %v, want ErrPageForbidden naming it", p.Key, p.Permission, err)
		}
		if !errors.Is(errNil, savedview.ErrPageForbidden) {
			t.Errorf("%s with no permission reader: %v, want ErrPageForbidden", p.Key, errNil)
		}
	}
	for _, key := range []string{"", "nope", "Findings", "scans.nope"} {
		if _, err := s.page(has(permission.FindingsRead.String()), key); !errors.Is(err, savedview.ErrUnknownPage) {
			t.Errorf("%q: %v, want ErrUnknownPage", key, err)
		}
	}
}

func TestNewService_RefusesAConfigOutsideTheRegistry(t *testing.T) {
	for name, pages := range map[string]map[string]PageConfig{
		"unregistered key":   {"nope": {}},
		"another permission": {savedview.PageFindings: {Permission: permission.AssetsRead.String()}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: NewService did not panic", name)
				}
			}()
			NewService(nil, pages, nil)
		}()
	}
}

func TestStateParams(t *testing.T) {
	long := strings.Repeat("v", savedview.MaxStateParamValueLen)
	many := map[string]string{}
	for i := range savedview.MaxStateParams + 1 {
		many["p"+strings.Repeat("a", i+1)] = "1"
	}
	for name, tc := range map[string]struct {
		in  Input
		err bool
	}{
		"none":                {in: Input{}},
		"empty filter":        {in: Input{Filter: []byte(" {} ")}},
		"state":               {in: Input{PageParams: map[string]string{"status": "open,done", "sort": "-created_at", "created.from": "2026-01-01", "x-y_z": ""}}},
		"longest value":       {in: Input{PageParams: map[string]string{"q": long}}},
		"filter document":     {in: Input{Filter: []byte(`{"severity":{"in":["high"]}}`)}, err: true},
		"query":               {in: Input{Query: "status=open"}, err: true},
		"too many":            {in: Input{PageParams: many}, err: true},
		"value too long":      {in: Input{PageParams: map[string]string{"q": long + "v"}}, err: true},
		"too many bytes":      {in: Input{PageParams: map[string]string{"a": long, "b": long, "c": long}}, err: true},
		"upper-case name":     {in: Input{PageParams: map[string]string{"Status": "open"}}, err: true},
		"empty name":          {in: Input{PageParams: map[string]string{"": "open"}}, err: true},
		"name with markup":    {in: Input{PageParams: map[string]string{"<b>": "open"}}, err: true},
		"control character":   {in: Input{PageParams: map[string]string{"q": "a\nb"}}, err: true},
		"invalid utf-8 value": {in: Input{PageParams: map[string]string{"q": "a\xffb"}}, err: true},
	} {
		got, err := stateParams(tc.in)
		if tc.err != (err != nil) || (err != nil && !errors.Is(err, savedview.ErrInvalid)) {
			t.Errorf("%s: err = %v, want error %v (ErrInvalid)", name, err, tc.err)
		}
		if err == nil && len(got) != len(tc.in.PageParams) {
			t.Errorf("%s: kept %d of %d params", name, len(got), len(tc.in.PageParams))
		}
	}
	// The stored map is a copy: the request map is not kept.
	sent := map[string]string{"q": "x"}
	got, _ := stateParams(Input{PageParams: sent})
	sent["q"] = "changed"
	if got["q"] != "x" {
		t.Error("the stored params alias the request map")
	}
}
