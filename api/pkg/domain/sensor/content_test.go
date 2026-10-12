package sensor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func trivyDB(updated time.Duration, errText string) ReportedContent {
	return ReportedContent{
		Tool: "trivy", Name: ContentTrivyDB, Version: "2026-09-29T01:05:41Z",
		UpdatedAt: ago(updated), Digest: "sha256:3b16", Managed: true, Error: errText,
	}
}

// withContent stores items on the sensor's reported tool inventory, grouped
// by tool, as a heartbeat would (no admin tool limit, all installed).
func withContent(s *Sensor, items []ReportedContent) {
	s.Reported.Tools = nil
	idx := map[string]int{}
	for _, c := range items {
		tool := c.Tool
		c.Tool = ""
		i, ok := idx[tool]
		if !ok {
			i = len(s.Reported.Tools)
			idx[tool] = i
			s.Reported.Tools = append(s.Reported.Tools, ReportedTool{Name: tool, Installed: true})
		}
		s.Reported.Tools[i].Content = append(s.Reported.Tools[i].Content, c)
	}
}

func TestSanitizeReportedContent(t *testing.T) {
	future := testNow.Add(72 * time.Hour)
	in := []ReportedContent{
		{Tool: "trivy", Name: ContentTrivyDB, Version: strings.Repeat("v", 300), Digest: "sha256:ABC", UpdatedAt: &future,
			Source: "mirror.gcr.io/aquasec/trivy-db:2\n", Error: "boom\x07" + strings.Repeat("é", 200), Managed: true},
		{Tool: "trivy", Name: ContentTrivyDB},    // duplicate
		{Tool: "trivy", Name: "Bad Name"},        // invalid name
		{Tool: "", Name: ContentNucleiTemplates}, // no tool
		{Tool: "nuclei", Name: ContentNucleiTemplates, Digest: "sha256:abcdef", FetchedAt: ago(time.Hour)},
	}
	for i := range 20 {
		in = append(in, ReportedContent{Tool: "semgrep", Name: "x" + strings.Repeat("y", i%5) + string(rune('a'+i))})
	}
	out := SanitizeReportedContent(in, testNow)

	if out[0].Tool != "trivy" || len(out[0].Version) != 128 || out[0].Digest != "" || out[0].UpdatedAt != nil {
		t.Errorf("trivy not sanitized: %+v", out[0])
	}
	if out[0].Source != "mirror.gcr.io/aquasec/trivy-db:2" {
		t.Errorf("source = %q", out[0].Source)
	}
	if len(out[0].Error) > 256 || strings.ContainsRune(out[0].Error, 0x07) || !strings.HasPrefix(out[0].Error, "boom") {
		t.Errorf("error = %q (%d bytes)", out[0].Error, len(out[0].Error))
	}
	if out[1].Name != ContentNucleiTemplates || out[1].Digest != "sha256:abcdef" || out[1].FetchedAt == nil {
		t.Errorf("nuclei = %+v", out[1])
	}
	semgrep := 0
	for _, c := range out {
		if c.Tool == "semgrep" {
			semgrep++
		}
	}
	if semgrep != MaxReportedContentPerTool || len(out) != 2+MaxReportedContentPerTool {
		t.Errorf("per-tool cap: semgrep=%d total=%d", semgrep, len(out))
	}

	if SanitizeReportedContent(nil, testNow) != nil {
		t.Error("nil input must stay nil (not reported)")
	}
	if got := SanitizeReportedContent([]ReportedContent{}, testNow); got == nil || len(got) != 0 {
		t.Error("empty input must stay empty, non-nil (reported none)")
	}
}

func TestContentViews_StaleAndPin(t *testing.T) {
	p := DefaultContentPolicy()
	p.Content[ContentNucleiTemplates] = ContentPin{MaxAgeHours: 336, Version: "v10.4.9"}

	s := daemon(ago(10 * time.Second))
	withContent(s, []ReportedContent{
		trivyDB(72*time.Hour, ""),
		{Tool: "nuclei", Name: ContentNucleiTemplates, Version: "v10.4.8", UpdatedAt: ago(24 * time.Hour), Managed: true},
		{Tool: "semgrep", Name: ContentSemgrepRules, Version: "auto", Managed: false, FetchedAt: ago(9999 * time.Hour)},
	})
	views := s.ContentViews(testNow, p)
	if len(views) != 3 {
		t.Fatalf("views = %d", len(views))
	}
	if !views[0].Stale || views[0].MaxAgeHours != 48 || views[0].AgeSeconds == nil || *views[0].AgeSeconds != 72*3600 {
		t.Errorf("trivy view = %+v", views[0])
	}
	if views[1].Stale || !views[1].PinMismatch || views[1].PinnedVersion != "v10.4.9" {
		t.Errorf("nuclei view = %+v", views[1])
	}
	if views[2].Stale || views[2].PinMismatch {
		t.Errorf("unmanaged content flagged: %+v", views[2])
	}

	// A digest pin matches the digest.
	p.Content[ContentTrivyDB] = ContentPin{MaxAgeHours: 48, Version: "sha256:3b16"}
	if v := s.ContentViews(testNow, p)[0]; v.PinMismatch {
		t.Errorf("digest pin should match: %+v", v)
	}
	if (&Sensor{}).ContentViews(testNow, p) == nil {
		t.Error("views must never be nil")
	}
}

func TestContentReasons(t *testing.T) {
	hp := testPolicy()

	s := daemon(ago(10 * time.Second))
	withContent(s, []ReportedContent{trivyDB(72*time.Hour, "registry unreachable.")})
	h := s.AssessHealth(testNow, hp)
	if h.State != StateDegraded || !hasCode(h.Reasons, ReasonContentStale) {
		t.Fatalf("stale content: state=%s reasons=%v", h.State, codes(h.Reasons))
	}
	msg := h.Reasons[0].Message
	if msg != "The trivy DB is 3d old (limit 2d). The last refresh failed: registry unreachable." {
		t.Errorf("message = %q", msg)
	}

	// Fresh but the last refresh failed: refresh_failed, plural wording.
	withContent(s, []ReportedContent{{Tool: "nuclei", Name: ContentNucleiTemplates, Version: "v10.4.8",
		UpdatedAt: ago(48 * time.Hour), Managed: true, Error: "checksum mismatch"}})
	h = s.AssessHealth(testNow, hp)
	if !hasCode(h.Reasons, ReasonContentRefreshFailed) || hasCode(h.Reasons, ReasonContentStale) {
		t.Fatalf("refresh failed: %v", codes(h.Reasons))
	}
	if got := h.Reasons[0].Message; got != "Refreshing the nuclei templates failed: checksum mismatch. Scans use v10.4.8." {
		t.Errorf("message = %q", got)
	}

	// A tenant policy with a larger limit: no longer stale.
	withContent(s, []ReportedContent{trivyDB(72*time.Hour, "")})
	hp.Content = &ContentPolicy{Content: map[string]ContentPin{ContentTrivyDB: {MaxAgeHours: 96}}}
	if h := s.AssessHealth(testNow, hp); len(h.Reasons) != 0 || h.State != StateOnline {
		t.Errorf("within tenant limit: %s %v", h.State, codes(h.Reasons))
	}

	// Stale with nothing installed yet.
	withContent(s, []ReportedContent{{Tool: "trivy", Name: ContentTrivyDB, Managed: true, Error: "no route to host"}})
	hp.Content = nil
	h = s.AssessHealth(testNow, hp)
	if !hasCode(h.Reasons, ReasonContentStale) || !strings.HasPrefix(h.Reasons[0].Message, "The trivy DB is missing") {
		t.Errorf("missing content: %v %q", codes(h.Reasons), h.Reasons)
	}

	// Unmanaged content never makes a sensor degraded.
	withContent(s, []ReportedContent{{Tool: "semgrep", Name: ContentSemgrepRules, Managed: false, Error: "x", FetchedAt: ago(9999 * time.Hour)}})
	if h := s.AssessHealth(testNow, hp); len(h.Reasons) != 0 {
		t.Errorf("unmanaged flagged: %v", codes(h.Reasons))
	}
}

// sdk-go ContentInfo.Stale: old content the sensor keeps confirming as the
// newest release (nuclei-templates whose latest release is 15 days old) is
// not stale; once the confirmation is older than the limit too, it is.
func TestContentStale_CheckedAt(t *testing.T) {
	hp := testPolicy()
	s := daemon(ago(10 * time.Second))
	nt := ReportedContent{Tool: "nuclei", Name: ContentNucleiTemplates, Version: "v10.4.9",
		UpdatedAt: ago(15 * 24 * time.Hour), CheckedAt: ago(time.Hour), Managed: true}
	withContent(s, []ReportedContent{nt})
	if h := s.AssessHealth(testNow, hp); len(h.Reasons) != 0 || h.State != StateOnline {
		t.Fatalf("confirmed newest release flagged: %s %v", h.State, codes(h.Reasons))
	}
	v := s.ContentViews(testNow, DefaultContentPolicy())[0]
	if v.Stale || v.CheckedAt == nil {
		t.Fatalf("view %+v", v)
	}

	nt.CheckedAt = ago(15 * 24 * time.Hour)
	nt.Error = "github unreachable"
	withContent(s, []ReportedContent{nt})
	h := s.AssessHealth(testNow, hp)
	if !hasCode(h.Reasons, ReasonContentStale) {
		t.Fatalf("unconfirmed for 15d: %v", codes(h.Reasons))
	}
	want := "The nuclei templates are 15d old (limit 14d). The sensor has not confirmed a newer version for 15d. The last refresh failed: github unreachable."
	if h.Reasons[0].Message != want {
		t.Errorf("message = %q", h.Reasons[0].Message)
	}

	// A checked_at in the far future is dropped at ingest.
	future := testNow.Add(72 * time.Hour)
	out := SanitizeReportedContent([]ReportedContent{{Tool: "nuclei", Name: ContentNucleiTemplates, CheckedAt: &future}}, testNow)
	if out[0].CheckedAt != nil {
		t.Errorf("future checked_at kept: %v", out[0].CheckedAt)
	}
}

func TestSupportsContentRefresh(t *testing.T) {
	s := &Sensor{}
	if s.SupportsContentRefresh() {
		t.Error("no content")
	}
	withContent(s, []ReportedContent{{Tool: "semgrep", Name: ContentSemgrepRules}})
	if s.SupportsContentRefresh() {
		t.Error("only unmanaged content")
	}
	withContent(s, append(s.ReportedContent(), trivyDB(time.Hour, "")))
	if !s.SupportsContentRefresh() {
		t.Error("managed content")
	}
}

func TestContentPolicyValidateAndDefaults(t *testing.T) {
	ok := ContentPolicy{RefreshIntervalHours: 12, Content: map[string]ContentPin{
		ContentTrivyDB:      {MaxAgeHours: 24, Version: "sha256:3b169afd"},
		ContentSemgrepRules: {Rulesets: []string{"p/default", "p/owasp-top-ten"}},
	}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	bad := []ContentPolicy{
		{RefreshIntervalHours: -1},
		{RefreshIntervalHours: MaxContentPolicyHours + 1},
		{Content: map[string]ContentPin{"unknown": {}}},
		{Content: map[string]ContentPin{ContentTrivyDB: {MaxAgeHours: -1}}},
		{Content: map[string]ContentPin{ContentTrivyDB: {Version: "--db-repository=x"}}},
		{Content: map[string]ContentPin{ContentTrivyDB: {Version: "a b"}}},
		{Content: map[string]ContentPin{ContentTrivyDB: {Version: strings.Repeat("a", 129)}}},
		{Content: map[string]ContentPin{ContentTrivyDB: {Rulesets: []string{"p/default"}}}},
		{Content: map[string]ContentPin{ContentSemgrepRules: {Rulesets: []string{"-c"}}}},
		{Content: map[string]ContentPin{ContentSemgrepRules: {Rulesets: []string{""}}}},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("bad policy %d accepted: %+v", i, p)
		}
	}

	eff := ok.WithDefaults(DefaultContentPolicy())
	if eff.RefreshIntervalHours != 12 || eff.Pin(ContentTrivyDB).MaxAgeHours != 24 ||
		eff.Pin(ContentNucleiTemplates).MaxAgeHours != 336 || eff.Pin(ContentSemgrepRules).MaxAgeHours != 168 ||
		len(eff.Pin(ContentSemgrepRules).Rulesets) != 2 || eff.Pin(ContentTrivyDB).Version != "sha256:3b169afd" {
		t.Errorf("effective = %+v", eff)
	}
	if got := (ContentPolicy{}).WithDefaults(DefaultContentPolicy()); got.RefreshIntervalHours != 6 || len(got.Content) != 4 {
		t.Errorf("empty policy with defaults = %+v", got)
	}
}

// Content rides on its tool through the capability report's sanitizer and
// the reported_tools JSON (RFC-031 stores it there, no column of its own).
func TestCapabilityReportCarriesContent(t *testing.T) {
	in := CapabilityReportInput{Tools: []ReportedTool{
		{Name: "trivy", Installed: true, Content: []ReportedContent{
			{Name: ContentTrivyDB, Version: "2026-10-02T01:05:41Z", Digest: "sha256:3b16", Managed: true},
			{Name: "Bad Name"},
		}},
		{Name: "unknown-tool", Installed: true, Content: []ReportedContent{{Name: ContentTrivyDB}}},
		{Name: "semgrep", Installed: true},
	}}
	r := in.Sanitize(map[string]bool{"trivy": true, "semgrep": true}, nil)
	if len(r.Tools) != 2 {
		t.Fatalf("tools = %+v", r.Tools)
	}
	if got := r.Tools[0].Content; len(got) != 1 || got[0].Name != ContentTrivyDB || got[0].Tool != "" || got[0].Digest != "sha256:3b16" {
		t.Fatalf("trivy content = %+v", got)
	}
	if r.Tools[1].Content != nil {
		t.Fatalf("semgrep reported no content: %+v", r.Tools[1].Content)
	}
	raw, err := json.Marshal(r.Tools)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"tool"`) || !strings.Contains(string(raw), `"content":[{"name":"trivy-db"`) {
		t.Fatalf("stored JSON = %s", raw)
	}
	s := &Sensor{Reported: r}
	flat := s.ReportedContent()
	if len(flat) != 1 || flat[0].Tool != "trivy" || !s.SupportsContentRefresh() {
		t.Fatalf("flattened = %+v", flat)
	}
}

// Sensors up to v0.6.1 report managed content that is still being installed
// with the error "not installed yet". It is missing, not a failed refresh.
func TestReportedContent_NotInstalledYetIsNotAnError(t *testing.T) {
	a := &Sensor{Reported: CapabilityReport{Tools: []ReportedTool{{Name: "nuclei", Content: []ReportedContent{
		{Name: "nuclei-templates", Managed: true, Error: "not installed yet"},
		{Name: "other", Managed: true, Version: "v1", Error: "not installed yet"},
	}}}}}
	got := a.ReportedContent()
	if got[0].Error != "" {
		t.Errorf("version-less content: error %q, want none", got[0].Error)
	}
	if got[1].Error == "" {
		t.Error("content with a version keeps its error")
	}
	flagged := false
	for _, r := range a.contentReasons(time.Now(), nil) {
		if !strings.Contains(r.Message, "nuclei templates") {
			continue
		}
		flagged = true
		if r.Code != ReasonContentStale || strings.Contains(r.Message, "failed") {
			t.Errorf("reason %+v: want missing (content_stale), not a failed refresh", r)
		}
	}
	if !flagged {
		t.Error("missing managed content is still flagged by the age limit")
	}
}
