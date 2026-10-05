package v2

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func TestParseResultsContentType(t *testing.T) {
	ok := []string{
		"application/vnd.openctem.ctis.v1+json",
		"Application/VND.OpenCTEM.CTIS.v1+JSON",
		"application/vnd.openctem.ctis.v1+json; charset=utf-8",
		"application/vnd.openctem.ctis.v1+json;charset=UTF-8",
		`application/vnd.openctem.ctis.v1+json; charset="utf-8"`,
	}
	for _, v := range ok {
		if err := ParseResultsContentType(v); err != nil {
			t.Errorf("%q refused: %v", v, err)
		}
	}
	bad := []string{
		"",
		"application/json",
		"application/json; charset=utf-8",
		"text/plain",
		"application/sarif+json",
		"application/vnd.openctem.ctis+json",
		"application/vnd.openctem.ctis+json; version=1",
		"application/vnd.openctem.ctis.v2+json",
		"application/vnd.openctem.ctis.v1+json; charset=latin1",
		"application/vnd.openctem.ctis.v1+json; version=1",
		"application/vnd.openctem.ctis.v1+json; charset=utf-8; x=y",
		"application/vnd.openctem.ctis.v1+json,application/json",
		"application/vnd.openctem.ctis.v1+json;;",
	}
	for _, v := range bad {
		if err := ParseResultsContentType(v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestParseContentEncoding(t *testing.T) {
	cases := []struct {
		in   []string
		want string
		err  bool
	}{
		{nil, "", false},
		{[]string{""}, "", false},
		{[]string{"identity"}, "", false},
		{[]string{"gzip"}, "gzip", false},
		{[]string{" GZIP "}, "gzip", false},
		{[]string{"zstd"}, "zstd", false},
		{[]string{"br"}, "", true},
		{[]string{"deflate"}, "", true},
		{[]string{"gzip, zstd"}, "", true},
		{[]string{"gzip", "gzip"}, "", true},
	}
	for _, c := range cases {
		got, err := ParseContentEncoding(c.in)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%q: got %q, %v", c.in, got, err)
		}
	}
}

func TestParseContentDigest(t *testing.T) {
	s256 := sha256.Sum256([]byte("x"))
	s512 := sha512.Sum512([]byte("x"))
	b256 := base64.StdEncoding.EncodeToString(s256[:])
	b512 := base64.StdEncoding.EncodeToString(s512[:])

	d, err := ParseContentDigest([]string{"sha-256=:" + b256 + ":"})
	if err != nil || !bytes.Equal(d[DigestSHA256], s256[:]) {
		t.Fatalf("sha-256: %v %v", d, err)
	}
	d, err = ParseContentDigest([]string{"sha-512=:" + b512 + ":, sha-256=:" + b256 + ":"})
	if err != nil || len(d) != 2 {
		t.Fatalf("both: %v %v", d, err)
	}
	// An unknown algorithm is ignored next to a known one.
	if _, err := ParseContentDigest([]string{"md5=:AAAA:, sha-256=:" + b256 + ":"}); err != nil {
		t.Fatalf("ignored unknown: %v", err)
	}
	missing := [][]string{nil, {"md5=:AAAA:"}, {"unixsum=:AAAA:"}}
	for _, v := range missing {
		if _, err := ParseContentDigest(v); err != ErrDigestMissing {
			t.Errorf("%q: want missing, got %v", v, err)
		}
	}
	malformed := [][]string{
		{""},
		{"sha-256"},
		{"sha-256=" + b256},
		{"SHA-256=:" + b256 + ":"},
		{"sha-256=:" + b256},
		{"sha-256=:not base64!:"},
		{"sha-256=:" + b512 + ":"},
		{"sha-256=:" + b256 + ":, sha-256=:" + b256 + ":"},
		{"sha-256=:" + b256 + ":;param=1"},
		{"sha-256=:" + b256 + ":,"},
	}
	for _, v := range malformed {
		if _, err := ParseContentDigest(v); err != ErrDigestMalformed {
			t.Errorf("%q: want malformed, got %v", v, err)
		}
	}
	if got, ok := CanonicalSHA256("sha-256=:" + b256 + ":"); !ok || got != FormatSHA256(s256[:]) {
		t.Errorf("canonical: %q %v", got, ok)
	}
	if _, ok := CanonicalSHA256("sha-512=:" + b512 + ":"); ok {
		t.Error("canonical sha-256 from a sha-512-only value")
	}
}

func TestIDs(t *testing.T) {
	good := []string{"0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b", "550e8400-e29b-41d4-a716-446655440000"}
	for _, s := range good {
		if ValidateUUID(s) != nil {
			t.Errorf("%q refused", s)
		}
	}
	bad := []string{"", "0192A3B4-5C6D-7E8F-9A0B-1C2D3E4F5A6B", "0192a3b45c6d7e8f9a0b1c2d3e4f5a6b",
		"{0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b}", nilUUID, "0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b ", "../x"}
	for _, s := range bad {
		if ValidateUUID(s) == nil {
			t.Errorf("%q accepted", s)
		}
	}
	for _, s := range []string{"0", "1", "255"} {
		if _, err := ParseSegmentSeq(s, 256); err != nil {
			t.Errorf("seq %q refused", s)
		}
	}
	for _, s := range []string{"", "-1", "+1", "01", "256", "1e2", "0x1", "99999999999"} {
		if _, err := ParseSegmentSeq(s, 256); err == nil {
			t.Errorf("seq %q accepted", s)
		}
	}
}

func TestHasFeatureAndVersion(t *testing.T) {
	if !HasFeature([]string{"doorbell, Results"}, FeatureResults) {
		t.Error("feature not found")
	}
	if HasFeature([]string{"doorbell"}, FeatureResults) {
		t.Error("feature found")
	}
	for _, v := range []string{"1", "1.0", "1.3"} {
		if !CTISVersionMajorMatches(v) {
			t.Errorf("%q", v)
		}
	}
	for _, v := range []string{"", "2", "2.0", "10.1", "v1", " .1"} {
		if CTISVersionMajorMatches(v) {
			t.Errorf("%q matched", v)
		}
	}
}

func TestNewProblemUnknownIsInternal(t *testing.T) {
	p := NewProblem("no-such-type")
	if p.ProblemType() != ProblemInternal || p.Status != 500 {
		t.Fatalf("got %v", p)
	}
}

func TestProblemHeaders(t *testing.T) {
	cases := map[ProblemType][2]string{
		ProblemUnsupportedMediaType: {"Accept", MediaTypeCTIS},
		ProblemUnsupportedEncoding:  {"Accept-Encoding", AcceptEncodingValue},
		ProblemRateLimited:          {"Retry-After", DefaultRetryAfterSeconds},
	}
	for pt, hv := range cases {
		rec := httptest.NewRecorder()
		NewProblem(pt).Write(rec)
		if got := rec.Header().Get(hv[0]); got != hv[1] {
			t.Errorf("%s: %s = %q", pt, hv[0], got)
		}
		if rec.Header().Get(HeaderProtocol) != "2" || rec.Header().Get("Content-Type") != MediaTypeProblem {
			t.Errorf("%s: headers %v", pt, rec.Header())
		}
	}
}

// TestProblemGolden pins every problem type's wire bytes: status, type URI,
// title, detail, retryable. A change here is a protocol change.
func TestProblemGolden(t *testing.T) {
	types := ProblemTypes()
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	var buf bytes.Buffer
	for _, pt := range types {
		rec := httptest.NewRecorder()
		NewProblem(pt).Write(rec)
		buf.WriteString("## " + string(pt) + "\n")
		keys := make([]string, 0, len(rec.Header()))
		for k := range rec.Header() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			buf.WriteString(k + ": " + strings.Join(rec.Header()[k], ",") + "\n")
		}
		buf.WriteString(rec.Body.String())
	}
	// Extension members.
	seg := 1
	rec := httptest.NewRecorder()
	NewProblem(ProblemSchemaInvalid).WithErrors([]ItemError{{Segment: &seg, Pointer: "/findings/17/severity", Code: CodeInvalidValue, Detail: DetailInvalidValue}}).Write(rec)
	buf.WriteString("## schema-invalid with errors\n" + rec.Body.String())
	rec = httptest.NewRecorder()
	NewProblem(ProblemContentTooLarge).WithLimit(DefaultMaxContentBytes).Write(rec)
	buf.WriteString("## content-too-large with limit\n" + rec.Body.String())
	golden(t, "problems.golden", buf.Bytes())
}

func TestStatusAndHelloGolden(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	seg := 1
	three := 3
	st := Status{
		ReportID:     "0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b",
		CommandID:    "0192a3b4-0000-7e8f-9a0b-1c2d3e4f5a6b",
		State:        StateCompleted,
		Segments:     SegmentCounts{Received: 3, Expected: &three},
		Accepted:     Counts{Assets: 120, Findings: 812},
		Rejected:     Counts{Findings: 4},
		AutoResolved: 37,
		AutoResolve:  AutoResolveApplied,
		Errors: []ItemError{{Segment: &seg, Pointer: "/findings/17/asset_ref",
			Code: CodeAssetUnresolved, Detail: DetailAssetUnresolved}},
		ReceivedAt: at,
		UpdatedAt:  at.Add(time.Minute),
	}
	receiving := Status{ReportID: st.ReportID, State: StateReceiving, Segments: SegmentCounts{Received: 1},
		Errors: []ItemError{}, ReceivedAt: at, UpdatedAt: at}
	var buf bytes.Buffer
	full := NewHello(DefaultLimits(), ControlFeatures()...).WithDeprecation("protocol_v1", Deprecation{
		DeprecatedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), SunsetAt: time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC)})
	for _, v := range []any{st, receiving, NewHello(DefaultLimits()), full} {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	golden(t, "status_hello.golden", buf.Bytes())
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s differs from golden (a v2 wire change; rerun with -update only if intended)\n--- got ---\n%s", name, got)
	}
}
