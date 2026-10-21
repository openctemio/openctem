package retestcheck

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAssertionValidate(t *testing.T) {
	ok := HTTPAssertion{Method: "GET", Path: "/x?y=1", Headers: map[string]string{"X-Test": "1"},
		Matchers: []Matcher{{Type: "status", Status: []int{200}}}}
	if issues := ok.Validate(); len(issues) != 0 {
		t.Fatalf("valid assertion refused: %+v", issues)
	}
	bad := map[string]HTTPAssertion{
		"method":          {Method: "DELETE", Path: "/", Matchers: ok.Matchers},
		"relative":        {Method: "GET", Path: "x", Matchers: ok.Matchers},
		"other host":      {Method: "GET", Path: "//evil.example/", Matchers: ok.Matchers},
		"space":           {Method: "GET", Path: "/a b", Matchers: ok.Matchers},
		"credential":      {Method: "GET", Path: "/", Headers: map[string]string{"Cookie": "s=1"}, Matchers: ok.Matchers},
		"host header":     {Method: "GET", Path: "/", Headers: map[string]string{"Host": "evil.example"}, Matchers: ok.Matchers},
		"header newline":  {Method: "GET", Path: "/", Headers: map[string]string{"X-A": "1\r\nX-B: 2"}, Matchers: ok.Matchers},
		"get body":        {Method: "GET", Path: "/", Body: "a", Matchers: ok.Matchers},
		"no matcher":      {Method: "GET", Path: "/"},
		"bad status":      {Method: "GET", Path: "/", Matchers: []Matcher{{Type: "status", Status: []int{99}}}},
		"bad part":        {Method: "GET", Path: "/", Matchers: []Matcher{{Type: "word", Part: "all", Words: []string{"a"}}}},
		"bad regex":       {Method: "GET", Path: "/", Matchers: []Matcher{{Type: "regex", Part: "body", Regex: []string{"("}}}},
		"dsl in path":     {Method: "GET", Path: "/{{env('HOME')}}", Matchers: ok.Matchers},
		"dsl in word":     {Method: "GET", Path: "/", Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"{{md5('a')}}"}}}},
		"unknown matcher": {Method: "GET", Path: "/", Matchers: []Matcher{{Type: "dsl"}}},
	}
	for name, a := range bad {
		if issues := a.Validate(); len(issues) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAssertionCompile(t *testing.T) {
	a := HTTPAssertion{Method: "post", Path: "/login", Body: "u=a", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Matchers: []Matcher{{Type: "word", Part: "header", Words: []string{"Set-Cookie"}, Negative: true}, {Type: "status", Status: []int{302}}}}
	out, err := a.Compile("abc")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"id: retest-check-abc", "method: POST", "'{{BaseURL}}/login'", "matchers-condition: and", "negative: true", "part: header"} {
		if !strings.Contains(s, want) {
			t.Errorf("compiled template lacks %q:\n%s", want, s)
		}
	}
	if _, err := (&HTTPAssertion{Method: "GET", Path: "x"}).Compile("abc"); err == nil {
		t.Fatal("an invalid assertion compiled")
	}
}

func TestCheckApprovalAndCalibration(t *testing.T) {
	author, other := shared.NewID(), shared.NewID()
	c := &Check{Tier: TierT1}
	if !c.Approved("sha256:a") {
		t.Fatal("a T1 check needs no approval")
	}
	if err := c.Approve(other, "sha256:a", time.Now()); !errors.Is(err, ErrApprovalNotNeeded) {
		t.Fatalf("want ErrApprovalNotNeeded, got %v", err)
	}
	c = &Check{Tier: TierT2}
	c.ContentChanged(&author)
	if c.Approved("sha256:a") {
		t.Fatal("an intrusive check runs without approval")
	}
	if err := c.Approve(author, "sha256:a", time.Now()); !errors.Is(err, ErrAuthorCannotApprove) {
		t.Fatalf("the author approved their own check: %v", err)
	}
	if err := c.Approve(other, "sha256:a", time.Now()); err != nil || !c.Approved("sha256:a") {
		t.Fatalf("second person approval: %v", err)
	}
	if c.Approved("sha256:b") {
		t.Fatal("approval carried over to other content")
	}
	c.CalibratedDigest = "sha256:a"
	if !c.Calibrated("sha256:a") || c.Calibrated("sha256:b") {
		t.Fatal("calibration is per digest")
	}
	c.ContentChanged(&other)
	if c.Approved("sha256:a") || c.Calibrated("sha256:a") {
		t.Fatal("a content change keeps approval or calibration")
	}
}
