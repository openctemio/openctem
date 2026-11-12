package query

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/querylang"
)

func parseService() *Service {
	s := NewService(nil, nil, nil)
	s.now = func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	return s
}

func caller(perms ...string) Caller {
	return Caller{TenantID: "11111111-1111-1111-1111-111111111111", UserID: "22222222-2222-2222-2222-222222222222",
		Has: func(p string) bool {
			for _, x := range perms {
				if x == p {
					return true
				}
			}
			return false
		}}
}

var readBoth = []string{permission.FindingsRead.String(), permission.AssetsRead.String()}

func TestParse_TextToDocumentChipsAndParams(t *testing.T) {
	res, err := parseService().Parse(context.Background(), caller(readBoth...), ParseInput{Entity: "findings",
		Text: `severity>=high kev=true -status:accepted last_seen<7d log4j`})
	if err != nil || !res.Valid {
		t.Fatalf("parse: %v %+v", err, res)
	}
	if res.Form != "short" || res.Text != "severity>=high is_in_kev=true status!=accepted last_seen_at<7d log4j" {
		t.Errorf("form %q text %q", res.Form, res.Text)
	}
	if !strings.HasPrefix(res.Query, "findings where ") {
		t.Errorf("query = %q", res.Query)
	}
	if res.Advanced || len(res.Chips) != 5 || res.Chips[4].Kind != "text" || res.Chips[0].Field != "severity" || res.Chips[0].Text != "severity>=high" {
		t.Errorf("chips = %+v", res.Chips)
	}
	want := map[string]string{"severity": "critical,high", "is_in_kev": "true", "status_not": "accepted", "last_seen_at_gt": "-P7D", "q": "log4j"}
	got, _ := json.Marshal(res.Params)
	wantJSON, _ := json.Marshal(want)
	if string(got) != string(wantJSON) {
		t.Errorf("params = %s, want %s", got, wantJSON)
	}
}

func TestParse_AdvancedNeverFlattened(t *testing.T) {
	res, err := parseService().Parse(context.Background(), caller(readBoth...), ParseInput{Entity: "findings",
		Text: `(severity=critical OR kev=true) tool=nuclei`})
	if err != nil || !res.Valid {
		t.Fatalf("parse: %v %+v", err, res)
	}
	if !res.Advanced || len(res.Chips) != 1 || res.Chips[0].Kind != "advanced" || res.Chips[0].Text != res.Text || res.Params != nil {
		t.Errorf("advanced = %v chips %+v params %v", res.Advanced, res.Chips, res.Params)
	}
}

func TestParse_ParamsAndDocumentInputs(t *testing.T) {
	s := parseService()
	res, err := s.Parse(context.Background(), caller(readBoth...), ParseInput{Entity: "findings",
		Params: "severity=critical,high&is_in_kev=true&last_seen_at_gt=-P7D&q=log4j&page=2&sort=-severity"})
	if err != nil || !res.Valid {
		t.Fatalf("params: %v %+v", err, res)
	}
	if res.Text != "is_in_kev=true last_seen_at<7d severity>=high log4j" {
		t.Errorf("params text = %q", res.Text)
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(`{"v":1,"filter":{"any":[{"field":"asset_ip","op":"in","value":["10.0.0.0/8"]},{"field":"cve_id","op":"in","value":["CVE-2024-3400"]}]}}`), &doc)
	res, err = s.Parse(context.Background(), caller(readBoth...), ParseInput{Entity: "findings", Document: doc})
	if err != nil || !res.Valid || res.Text != "asset.ip=10.0.0.0/8 OR cve_id=CVE-2024-3400" || !res.Advanced {
		t.Fatalf("document: %v %+v", err, res)
	}
	// Unknown params are not a filter: a bad request, never a wider read.
	if _, err := s.Parse(context.Background(), caller(readBoth...), ParseInput{Entity: "findings", Params: "severity=bogus"}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad params: %v", err)
	}
	if _, err := s.Parse(context.Background(), caller(readBoth...), ParseInput{Entity: "findings", Text: "x", Params: "q=x"}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("two inputs: %v", err)
	}
}

func TestParse_PermissionsAndProblems(t *testing.T) {
	s := parseService()
	ctx := context.Background()
	if _, err := s.Parse(ctx, caller(permission.AssetsRead.String()), ParseInput{Entity: "findings", Text: "x"}); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("no findings:read: %v", err)
	}
	if _, err := s.Parse(ctx, caller(readBoth...), ParseInput{Entity: "secrets", Text: "x"}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("unknown entity: %v", err)
	}
	findingsOnly := caller(permission.FindingsRead.String())
	res, err := s.Parse(ctx, findingsOnly, ParseInput{Entity: "findings", Text: "10.1.2.3"})
	if err != nil || !res.Valid || res.Params["q"] != "10.1.2.3" {
		t.Errorf("bare address without assets:read: %v %+v", err, res)
	}
	res, err = s.Parse(ctx, findingsOnly, ParseInput{Entity: "findings", Text: "ip=10.1.2.3"})
	if err != nil || res.Valid || len(res.Problems) != 1 || res.Problems[0].Code != querylang.CodeUnknownField || res.Document != nil {
		t.Errorf("ip without assets:read: %v %+v", err, res)
	}
	res, _ = s.Parse(ctx, caller(readBoth...), ParseInput{Entity: "findings", Text: "severity=zzsecretzz"})
	b, _ := json.Marshal(res)
	if res.Valid || strings.Contains(string(b), "zzsecretzz") {
		t.Errorf("problem echoes the value: %s", b)
	}
	// A filter the list cannot run is a problem, not a document.
	res, _ = s.Parse(ctx, caller(readBoth...), ParseInput{Entity: "findings", Text: "log4j OR severity=high"})
	if res.Valid || len(res.Problems) != 1 || res.Problems[0].Code != CodeNotOnList {
		t.Errorf("not on list: %+v", res)
	}
}
