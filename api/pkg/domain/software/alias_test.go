package software

import (
	"errors"
	"strings"
	"testing"
)

func TestFeedAliasValidate(t *testing.T) {
	const target = "a:google:chrome"
	cases := []struct {
		name string
		a    FeedAlias
		ok   bool
	}{
		{"cpe", FeedAlias{Kind: AliasKindCPE, Value: "a:google_inc:chrome", Target: target}, true},
		{"purl", FeedAlias{Kind: AliasKindPURL, Value: "pkg:maven/org.apache.logging.log4j/log4j-core", Target: "a:apache:log4j", Basis: BasisCurated}, true},
		{"purl without namespace", FeedAlias{Kind: AliasKindPURL, Value: "pkg:npm/lodash", Target: "a:lodash:lodash", Basis: BasisCurated}, true},
		{"purl learned", FeedAlias{Kind: AliasKindPURL, Value: "pkg:npm/lodash", Target: "a:lodash:lodash", Basis: "learned"}, false},
		{"name kind", FeedAlias{Kind: "name", Value: "chrome", Target: target}, false},
		{"unknown kind", FeedAlias{Kind: "swid", Value: "x", Target: target}, false},
		{"upper case", FeedAlias{Kind: AliasKindCPE, Value: "a:Google:chrome", Target: target}, false},
		{"self", FeedAlias{Kind: AliasKindCPE, Value: target, Target: target}, false},
		{"oversized", FeedAlias{Kind: AliasKindCPE, Value: "a:x:" + strings.Repeat("y", MaxAliasValue), Target: target}, false},
		{"long component", FeedAlias{Kind: AliasKindCPE, Value: "a:x:" + strings.Repeat("y", 129), Target: target}, false},
		{"wildcard", FeedAlias{Kind: AliasKindCPE, Value: "a:*:chrome", Target: target}, false},
		{"control", FeedAlias{Kind: AliasKindCPE, Value: "a:x\n:chrome", Target: target}, false},
		{"four parts", FeedAlias{Kind: AliasKindCPE, Value: "a:x:y:z", Target: target}, false},
		{"bad part", FeedAlias{Kind: AliasKindCPE, Value: "q:x:y", Target: target}, false},
		{"bad target", FeedAlias{Kind: AliasKindCPE, Value: "a:x:y", Target: "google chrome"}, false},
		{"empty", FeedAlias{Kind: AliasKindCPE, Value: "", Target: target}, false},
		{"purl version", FeedAlias{Kind: AliasKindPURL, Value: "pkg:npm/lodash@4.17.21", Target: target, Basis: BasisCurated}, false},
		{"purl qualifiers", FeedAlias{Kind: AliasKindPURL, Value: "pkg:deb/debian/curl?arch=amd64", Target: target, Basis: BasisCurated}, false},
		{"not a purl", FeedAlias{Kind: AliasKindPURL, Value: "npm/lodash", Target: target, Basis: BasisCurated}, false},
	}
	for _, c := range cases {
		err := c.a.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok %v", c.name, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalidAlias) {
			t.Errorf("%s: %v is not ErrInvalidAlias", c.name, err)
		}
	}
}
