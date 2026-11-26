package feedstatus

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/openctemio/contract/transfer/bundle"

	"github.com/openctemio/openctem/server/pkg/domain/threatintel"
	"github.com/openctemio/openctem/server/pkg/feedsign"
)

func ptr(t time.Time) *time.Time { return &t }

func TestCompute(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ok := threatintel.SyncStateSuccess
	cases := []struct {
		name string
		in   Input
		want State
	}{
		{"off", Input{Source: SourceKEV, Enabled: false, Status: ok}, StateOff},
		{"kev fresh", Input{Source: SourceKEV, Enabled: true, Status: ok, LastSuccessAt: ptr(now.Add(-time.Hour))}, StateUpToDate},
		{"kev 7 h is fresh (bundle limit)", Input{Source: SourceKEV, Enabled: true, Status: ok, LastSuccessAt: ptr(now.Add(-7 * time.Hour))}, StateUpToDate},
		{"kev stale", Input{Source: SourceKEV, Enabled: true, Status: ok, LastSuccessAt: ptr(now.Add(-13 * time.Hour))}, StateStale},
		{"kev judged by the release date", Input{Source: SourceKEV, Enabled: true, Status: ok, LastSuccessAt: ptr(now), DataAsOf: ptr(now.Add(-13 * time.Hour))}, StateStale},
		{"kev under a raised limit", Input{Source: SourceKEV, Enabled: true, Status: ok, LastSuccessAt: ptr(now), DataAsOf: ptr(now.Add(-40 * time.Hour)), Limits: Limits{Vulnfeed: 48 * time.Hour}}, StateUpToDate},
		{"bundle under a raised limit", Input{Source: SourceVulnfeed, Enabled: true, Status: ok, LastSuccessAt: ptr(now), DataAsOf: ptr(now.Add(-40 * time.Hour)), HasAppliedData: true, Limits: Limits{Vulnfeed: 48 * time.Hour}}, StateUpToDate},
		{"epss 30 h is fresh", Input{Source: SourceEPSS, Enabled: true, Status: ok, LastSuccessAt: ptr(now.Add(-30 * time.Hour))}, StateUpToDate},
		{"running", Input{Source: SourceKEV, Enabled: true, Status: threatintel.SyncStateRunning, UpdatedAt: now.Add(-time.Minute)}, StateRunning},
		{"running forever is interrupted", Input{Source: SourceKEV, Enabled: true, Status: threatintel.SyncStateRunning, UpdatedAt: now.Add(-3 * time.Hour), LastSuccessAt: ptr(now.Add(-time.Hour))}, StateFailing},
		{"failing, data still fresh", Input{Source: SourceKEV, Enabled: true, Status: threatintel.SyncStateFailed, ErrorCode: CodeHTTPStatus, LastSuccessAt: ptr(now.Add(-2 * time.Hour))}, StateFailing},
		{"failing and data stale", Input{Source: SourceKEV, Enabled: true, Status: threatintel.SyncStateFailed, ErrorCode: CodeHTTPStatus, LastSuccessAt: ptr(now.Add(-13 * time.Hour))}, StateStale},
		{"never succeeded, failing", Input{Source: SourceKEV, Enabled: true, Status: threatintel.SyncStateFailed, ErrorCode: CodeUnreachable}, StateFailing},
		{"refused", Input{Source: SourceVulnfeed, Enabled: true, Status: threatintel.SyncStateFailed, ErrorCode: CodeSignatureInvalid, LastSuccessAt: ptr(now)}, StateRefused},
		{"waiting", Input{Source: SourceVulnfeed, Enabled: true, Status: threatintel.SyncStateFailed, ErrorCode: CodePublisherEmpty, FailingSince: ptr(now.Add(-time.Hour))}, StateWaitingForPublisher},
		{"waiting turns stale after 3 days", Input{Source: SourceVulnfeed, Enabled: true, Status: threatintel.SyncStateFailed, ErrorCode: CodePublisherEmpty, FailingSince: ptr(now.Add(-80 * time.Hour))}, StateStale},
		{"bundle old", Input{Source: SourceVulnfeed, Enabled: true, Status: ok, LastSuccessAt: ptr(now), DataAsOf: ptr(now.Add(-4 * 24 * time.Hour)), HasAppliedData: true}, StateStale},
		{"bundle recent", Input{Source: SourceVulnfeed, Enabled: true, Status: ok, LastSuccessAt: ptr(now), DataAsOf: ptr(now.Add(-time.Hour)), HasAppliedData: true}, StateUpToDate},
	}
	for _, c := range cases {
		if got := Compute(c.in, now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code string
	}{
		{"http", fmt.Errorf("x: %w", &HTTPError{Op: "kev fetch", Host: "www.cisa.gov", Status: 403}), CodeHTTPStatus},
		{"net", fmt.Errorf("get: %w", &url.Error{Op: "Get", URL: "https://example.com/a", Err: errors.New("dial")}), CodeUnreachable},
		{"timeout", context.DeadlineExceeded, CodeUnreachable},
		{"empty", fmt.Errorf("kev %w", ErrFeedEmpty), CodeEmptyFeed},
		{"shrunk", &GuardError{Base: ErrFeedShrunk, N: 1, Limit: 9, Msg: "m"}, CodeGuardRefused},
		{"keyset", fmt.Errorf("key set: %w", feedsign.ErrKeySetRollback), CodeKeysetRollback},
		{"sig", fmt.Errorf("x: %w", bundle.ErrSignature), CodeSignatureInvalid},
		{"rollback", fmt.Errorf("x: %w", bundle.ErrRollback), CodeSequenceRollback},
		{"expired", fmt.Errorf("x: %w", bundle.ErrExpired), CodeExpired},
		{"disabled", threatintel.ErrSyncDisabled, CodeDisabled},
		{"other", errors.New("boom"), CodeFailed},
		{"tagged", Tag(CodePublisherEmpty, map[string]string{"host": "h"}, errors.New("404")), CodePublisherEmpty},
		{"verify expired", TagVerify(errors.New("latest: expired or valid too long")), CodeExpired},
		{"verify signature", TagVerify(errors.New("key set: bad root signature")), CodeSignatureInvalid},
		{"verify other", TagVerify(errors.New("snapshot manifest: file \"x\"")), CodeBundleInvalid},
	}
	for _, c := range cases {
		if got := Classify(c.err); got.Code != c.code {
			t.Errorf("%s: %q, want %q", c.name, got.Code, c.code)
		}
	}
	if p := Classify(&HTTPError{Host: "h", Status: 503}).Params; p["host"] != "h" || p["status"] != "503" {
		t.Errorf("params %v", p)
	}
	if Classify(nil).Code != "" {
		t.Error("nil classified")
	}
}

func TestBuild_NextRunUsesTheSchedulerInterval(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	st := threatintel.NewSyncStatus(SourceKEV, 24) // the row says 24 h; the controller runs hourly
	st.MarkSyncUnchanged(5, 1512)
	v := Build(st, 1512, time.Now())
	if v.NextRunAt == nil || v.NextRunAt.Sub(*v.LastAttemptAt) != time.Hour {
		t.Fatalf("next run %v after attempt %v", v.NextRunAt, v.LastAttemptAt)
	}
	// Overdue: the next run is now, never in the past.
	old := threatintel.ReconstituteSyncStatus(st.ID(), SourceKEV, ptr(now.Add(-5*time.Hour)), threatintel.SyncStateSuccess, "", 1512, 0, nil, 24, true, nil, now, now)
	if v := Build(old, 1512, now); v.NextRunAt == nil || !v.NextRunAt.Equal(now) {
		t.Fatalf("overdue next run %v", v.NextRunAt)
	}
	// Off: no next run.
	st.SetEnabled(false)
	if v := Build(st, 1512, now); v.NextRunAt != nil || v.State != StateOff {
		t.Fatalf("off: %+v", v)
	}
}

// KEV never goes stale before the bundle that carries it; EPSS takes a day
// more; the bundle limit stays within its bounds.
func TestLimits(t *testing.T) {
	d := DefaultLimits()
	if d.StaleAfter(SourceVulnfeed) != 12*time.Hour || d.StaleAfter(SourceKEV) != 12*time.Hour || d.StaleAfter(SourceEPSS) != 36*time.Hour {
		t.Fatalf("defaults %v %v %v", d.StaleAfter(SourceVulnfeed), d.StaleAfter(SourceKEV), d.StaleAfter(SourceEPSS))
	}
	if (Limits{}).StaleAfter(SourceKEV) != 12*time.Hour {
		t.Fatal("the zero value is not the default")
	}
	for _, h := range []time.Duration{time.Hour, 6 * time.Hour, 48 * time.Hour, 30 * 24 * time.Hour} {
		l := Limits{Vulnfeed: h}
		b := l.Bundle()
		if b < MinStaleAfterVulnfeed || b > MaxStaleAfterVulnfeed {
			t.Errorf("%v: bundle %v out of bounds", h, b)
		}
		if l.StaleAfter(SourceKEV) < l.StaleAfter(SourceVulnfeed) {
			t.Errorf("%v: KEV under the bundle limit", h)
		}
		e := l.StaleAfter(SourceEPSS)
		if e < StaleAfterEPSS || e < min(b+24*time.Hour, MaxBundleValidity) || e > MaxBundleValidity {
			t.Errorf("%v: EPSS %v", h, e)
		}
	}
}

// KEV and EPSS show the bundle import's next run and cycle, not an hourly
// or daily one of their own.
func TestAlignBundleCycle(t *testing.T) {
	next := time.Date(2026, 11, 25, 10, 20, 0, 0, time.UTC)
	views := []View{
		{Source: SourceVulnfeed, Enabled: true, Interval: IntervalVulnfeed, NextRunAt: &next},
		{Source: SourceKEV, Enabled: true, Interval: IntervalKEV, State: StateUpToDate},
		{Source: SourceEPSS, Enabled: true, Interval: IntervalEPSS, State: StateStale},
		{Source: SourceEPSS + "-off", Enabled: false},
	}
	AlignBundleCycle(views)
	for _, v := range views[1:3] {
		if v.Interval != IntervalVulnfeed || v.NextRunAt == nil || !v.NextRunAt.Equal(next) {
			t.Fatalf("%s: interval %v next %v", v.Source, v.Interval, v.NextRunAt)
		}
	}
	// The bundle import is off: KEV and EPSS have no next run either.
	views[0].Enabled = false
	AlignBundleCycle(views)
	if views[1].NextRunAt != nil {
		t.Fatalf("next run without a bundle import: %v", views[1].NextRunAt)
	}
}
