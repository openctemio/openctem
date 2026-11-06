package signer

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

func contentDigest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// The statement's content references are validated like the template digests
// (shape and number), and a signed statement carries them in the payload's
// order for the sensor to compare.
func TestSign_ContentReferences(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), nil)
	ref := func(slot, digest string) map[string]string { return map[string]string{"slot": slot, "digest": digest} }
	many := make([]map[string]string, jobsign.MaxContent+1)
	for i := range many {
		many[i] = ref("s"+strings.Repeat("a", i), contentDigest('a'))
	}
	cases := map[string][]map[string]string{
		"empty list":     {},
		"bad digest":     {ref("labels", "md5:abc")},
		"upper case":     {ref("labels", strings.ToUpper(contentDigest('a')))},
		"bad slot":       {ref("../labels", contentDigest('a'))},
		"empty slot":     {ref("", contentDigest('a'))},
		"a pack twice":   {ref("labels", contentDigest('a')), ref("labels", contentDigest('a'))},
		"too many packs": many,
	}
	for name, content := range cases {
		_, r := s.Sign(statement(func(m map[string]any) { m["content"] = content }))
		if r == nil || r.reason != ReasonBadContent {
			t.Errorf("%s: want %s, got %+v", name, ReasonBadContent, r)
		}
	}
	env, r := s.Sign(statement(func(m map[string]any) {
		m["content"] = []map[string]string{ref("labels", contentDigest('a')), ref("params", contentDigest('b'))}
	}))
	if r != nil {
		t.Fatalf("a valid content list was refused: %+v", r)
	}
	_, st := decodeEnvelope(t, env)
	if len(st.Content) != 2 || st.Content[0].Slot != "labels" || st.Content[1].Digest != contentDigest('b') {
		t.Fatalf("signed content = %+v", st.Content)
	}
	// Without content the member is left out of the signed bytes.
	plain, r := s.Sign(statement(nil))
	if r != nil {
		t.Fatalf("plain statement: %+v", r)
	}
	if e, _ := decodeEnvelope(t, plain); strings.Contains(string(e.Payload), `"content"`) {
		t.Fatalf("a statement without content carries the member: %s", e.Payload)
	}
}
