// Package feedstatus turns the stored progress of a platform-wide intelligence
// feed (EPSS, CISA KEV, the vulnerability bundles) into what an operator needs:
// one state, an error code with parameters, honest times. The server computes
// it once; the console and the organization routes only render it.
//
// Design: research notes on threat intelligence feeds, status model.
package feedstatus

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/contract/transfer/bundle"

	"github.com/openctemio/openctem/server/pkg/domain/threatintel"
	"github.com/openctemio/openctem/server/pkg/feedsign"
)

// Sources.
const (
	SourceEPSS     = "epss"
	SourceKEV      = "kev"
	SourceVulnfeed = "vulnfeed"
)

// How often the controller of each feed runs. The controllers return these,
// so the "next run" the console shows is the scheduler's own interval.
const (
	IntervalEPSS     = 24 * time.Hour
	IntervalKEV      = time.Hour
	IntervalVulnfeed = 20 * time.Minute
)

// Data older than its limit is stale: the console shows the feed as stale,
// the administrators are alerted and every user sees the freshness banner
// (internal/app/feedwatch).
//
// KEV and EPSS arrive only inside the signed vulnerability release, so their
// limits follow the release's: releases are published every 2 to 6 hours,
// and a fixed KEV limit below the release limit made the banner come and go
// between two releases. KEV is judged, like the bundle, by the date the
// release carries (when the collector read it) against the bundle limit;
// EPSS scores are dated by day, so their limit is the bundle limit plus a
// day, never under 36 hours and never over the 7 days a release is valid.
// The default KEV limit moved from 6 to 12 hours with this.
//
// The limits also decide whether a release's KEV and EPSS side data counts
// as current (threat.IntelService.sourceStale): raising them loosens that
// acceptance, not only the banner.
//
// A platform administrator may raise the bundle limit for a site that
// copies releases by hand (Limits, console setting feed_freshness.limits);
// a release older than 7 days is still refused, whatever the limit.
const (
	// StaleAfterVulnfeed is the default limit of the bundle and KEV.
	StaleAfterVulnfeed = 12 * time.Hour
	// MinStaleAfterVulnfeed and MaxStaleAfterVulnfeed bound the setting:
	// under 6 hours the banner would come and go between releases; above
	// 7 days a release is refused as expired anyway.
	MinStaleAfterVulnfeed = 6 * time.Hour
	MaxStaleAfterVulnfeed = MaxBundleValidity
	// MaxBundleValidity is how long a release is accepted at all: an older
	// one is refused as expired. No derived limit goes beyond it.
	MaxBundleValidity = 7 * 24 * time.Hour
	// StaleAfterEPSS is the floor of the EPSS limit (scores are published
	// daily).
	StaleAfterEPSS = 36 * time.Hour
	// epssDayLag: EPSS scores are dated by day.
	epssDayLag = 24 * time.Hour
)

// Limits are the stale limits in force. The zero value is the default.
type Limits struct {
	// Vulnfeed is the limit of the bundle (and of KEV, which rides it);
	// 0 means StaleAfterVulnfeed.
	Vulnfeed time.Duration
}

// DefaultLimits are the limits without a console setting.
func DefaultLimits() Limits { return Limits{Vulnfeed: StaleAfterVulnfeed} }

// Bundle is the bundle limit in force, within its bounds.
func (l Limits) Bundle() time.Duration {
	if l.Vulnfeed <= 0 {
		return StaleAfterVulnfeed
	}
	return min(max(l.Vulnfeed, MinStaleAfterVulnfeed), MaxStaleAfterVulnfeed)
}

// StaleAfter is how old the data of a source may be (0: unknown source).
func (l Limits) StaleAfter(source string) time.Duration {
	switch source {
	case SourceVulnfeed, SourceKEV:
		return l.Bundle()
	case SourceEPSS:
		return min(max(StaleAfterEPSS, l.Bundle()+epssDayLag), MaxBundleValidity)
	}
	return 0
}

// runningTimeout: a row that has said "running" for longer than this was
// interrupted (the longest controller run is 45 minutes).
const runningTimeout = time.Hour

// RunningTimeout is how long a run may hold a feed before it counts as
// interrupted (and another run may claim the feed).
const RunningTimeout = runningTimeout

// Interval is the controller interval of a source (0: unknown source).
func Interval(source string) time.Duration {
	switch source {
	case SourceEPSS:
		return IntervalEPSS
	case SourceKEV:
		return IntervalKEV
	case SourceVulnfeed:
		return IntervalVulnfeed
	}
	return 0
}

// StaleAfter is how old the data of a source may be under the default
// limits.
func StaleAfter(source string) time.Duration { return DefaultLimits().StaleAfter(source) }

// State is the one word the console shows for a feed.
type State string

// States.
const (
	StateUpToDate            State = "up_to_date"
	StateWaitingForPublisher State = "waiting_for_publisher"
	StateStale               State = "stale"
	StateFailing             State = "failing"
	StateRefused             State = "refused"
	StateRunning             State = "running"
	StateOff                 State = "off"
)

// Error codes. The console translates them; the raw text stays in
// last_error on the platform admin route only.
const (
	CodePublisherEmpty   = "publisher_empty"
	CodeUnreachable      = "unreachable"
	CodeHTTPStatus       = "http_status"
	CodeSignatureInvalid = "signature_invalid"
	CodeKeysetRollback   = "keyset_rollback"
	CodeSequenceRollback = "sequence_rollback"
	CodeExpired          = "expired"
	CodeBundleInvalid    = "bundle_invalid"
	CodeGuardRefused     = "guard_refused"
	CodeEmptyFeed        = "empty_feed"
	CodeDisabled         = "disabled"
	CodeNotConfigured    = "not_configured"
	CodeInterrupted      = "interrupted"
	CodeFailed           = "failed"
	// CodeSourceStale: a signed release carried a feed (KEV, EPSS) the
	// collector last read longer ago than the feed's stale limit.
	CodeSourceStale = "source_stale"
)

// refused codes: a feed that verified and then refused what it was offered.
var refusedCodes = map[string]bool{
	CodeSignatureInvalid: true, CodeKeysetRollback: true, CodeSequenceRollback: true,
	CodeExpired: true, CodeGuardRefused: true, CodeBundleInvalid: true,
}

// Errors the fetchers return.
var (
	// ErrFeedEmpty: the source answered 200 but carried no entries.
	ErrFeedEmpty = errors.New("feed returned no entries")
	// ErrFeedShrunk: the snapshot is far smaller than the stored catalog.
	ErrFeedShrunk = errors.New("feed refused: snapshot smaller than the stored catalog")
	// ErrNotConfigured: the importer has no pinned root key.
	ErrNotConfigured = errors.New("vulnerability bundle import is not configured (VULNFEED_ROOT_KEY_ID is empty)")
)

// HTTPError is a fetch that got a status other than 200.
type HTTPError struct {
	Op     string // for the message, for example "vulnfeed fetch"
	File   string
	Host   string
	Status int
}

func (e *HTTPError) Error() string {
	if e.File == "" {
		return fmt.Sprintf("%s: status %d", e.Op, e.Status)
	}
	return fmt.Sprintf("%s %s: status %d", e.Op, e.File, e.Status)
}

// GuardError is a feed refused by a size guard.
type GuardError struct {
	Base error
	// Kind: GuardSnapshot (a snapshot under the share of the stored catalog)
	// or GuardRemoval (a bundle that would empty too many ranges).
	Kind  string
	Msg   string
	N     int64
	Limit int64
}

// Guard kinds.
const (
	GuardSnapshot = "snapshot"
	GuardRemoval  = "removal"
)

func (e *GuardError) Error() string { return e.Msg }
func (e *GuardError) Unwrap() error { return e.Base }

// CodedError carries a classification chosen where the cause is known.
type CodedError struct {
	Code   string
	Params map[string]string
	Err    error
}

func (e *CodedError) Error() string { return e.Err.Error() }
func (e *CodedError) Unwrap() error { return e.Err }

// Tag wraps err with a code; a nil err stays nil.
func Tag(code string, params map[string]string, err error) error {
	if err == nil {
		return nil
	}
	return &CodedError{Code: code, Params: params, Err: err}
}

// Classified is an error code with its parameters.
type Classified struct {
	Code   string
	Params map[string]string
}

// Classify maps a failure to a code.
func Classify(err error) Classified {
	if err == nil {
		return Classified{}
	}
	var coded *CodedError
	if errors.As(err, &coded) {
		return Classified{Code: coded.Code, Params: coded.Params}
	}
	var he *HTTPError
	if errors.As(err, &he) {
		p := map[string]string{"status": fmt.Sprint(he.Status)}
		if he.Host != "" {
			p["host"] = he.Host
		}
		return Classified{Code: CodeHTTPStatus, Params: p}
	}
	var ge *GuardError
	switch {
	case errors.As(err, &ge):
		return Classified{Code: CodeGuardRefused, Params: map[string]string{
			"kind": ge.Kind, "count": fmt.Sprint(ge.N), "limit": fmt.Sprint(ge.Limit)}}
	case errors.Is(err, ErrFeedShrunk):
		return Classified{Code: CodeGuardRefused}
	case errors.Is(err, ErrFeedEmpty):
		return Classified{Code: CodeEmptyFeed}
	case errors.Is(err, feedsign.ErrKeySetRollback):
		return Classified{Code: CodeKeysetRollback}
	case errors.Is(err, bundle.ErrSignature):
		return Classified{Code: CodeSignatureInvalid}
	case errors.Is(err, bundle.ErrRollback):
		return Classified{Code: CodeSequenceRollback}
	case errors.Is(err, bundle.ErrExpired):
		return Classified{Code: CodeExpired}
	case errors.Is(err, bundle.ErrInvalid), errors.Is(err, bundle.ErrPinMismatch), errors.Is(err, bundle.ErrChunk):
		return Classified{Code: CodeBundleInvalid}
	case errors.Is(err, threatintel.ErrSyncDisabled):
		return Classified{Code: CodeDisabled}
	case errors.Is(err, ErrNotConfigured):
		return Classified{Code: CodeNotConfigured}
	}
	var ne net.Error
	var ue *url.Error
	if errors.As(err, &ue) {
		return Classified{Code: CodeUnreachable, Params: hostParam(ue.URL)}
	}
	if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) {
		return Classified{Code: CodeUnreachable}
	}
	return Classified{Code: CodeFailed}
}

func hostParam(raw string) map[string]string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return map[string]string{"host": u.Host}
	}
	return nil
}

// MetaDataAsOf is the metadata key for the date of the data a feed holds
// (EPSS: the score date).
const MetaDataAsOf = "data_as_of"

// Input is what State needs.
type Input struct {
	Source         string
	Enabled        bool
	Status         threatintel.SyncState
	UpdatedAt      time.Time
	LastSuccessAt  *time.Time
	FailingSince   *time.Time
	ErrorCode      string
	DataAsOf       *time.Time
	HasAppliedData bool // vulnfeed: a bundle was applied
	// Limits are the stale limits in force (zero: the defaults).
	Limits Limits
}

// Compute is the one state of a feed.
func Compute(in Input, now time.Time) State {
	if !in.Enabled {
		return StateOff
	}
	if in.Status == threatintel.SyncStateRunning && now.Sub(in.UpdatedAt) < runningTimeout {
		return StateRunning
	}
	failed := in.Status == threatintel.SyncStateFailed ||
		(in.Status == threatintel.SyncStateRunning) // a run that never finished
	stale := in.isStale(now)
	if failed {
		code := in.ErrorCode
		if in.Status == threatintel.SyncStateRunning {
			code = CodeInterrupted
		}
		switch {
		case code == CodePublisherEmpty && !in.HasAppliedData:
			if in.FailingSince != nil && now.Sub(*in.FailingSince) > in.Limits.Bundle() {
				return StateStale
			}
			return StateWaitingForPublisher
		case refusedCodes[code]:
			return StateRefused
		case stale && in.LastSuccessAt != nil:
			return StateStale
		default:
			return StateFailing
		}
	}
	if in.Status == threatintel.SyncStatePending && in.LastSuccessAt == nil {
		// Never ran: nothing is wrong yet, nothing is fresh either.
		return StateStale
	}
	if stale {
		return StateStale
	}
	return StateUpToDate
}

// isStale: the data a feed holds is older than its threshold. The bundle
// feed is judged by the age of the newest bundle, KEV by the date the
// release carries (falling back to the last successful check), EPSS by the
// last successful check.
func (in Input) isStale(now time.Time) bool {
	limit := in.Limits.StaleAfter(in.Source)
	ref := in.LastSuccessAt
	switch in.Source {
	case SourceVulnfeed:
		ref = in.DataAsOf
	case SourceKEV:
		if in.DataAsOf != nil {
			ref = in.DataAsOf
		}
	}
	if ref == nil || limit == 0 {
		return ref == nil
	}
	return now.Sub(*ref) > limit
}

// TagVerify classifies an error returned by the whole-bundle (v1) verifier,
// which reports by message: a key set or envelope signature problem, an
// expired document, or any other refusal to trust the bundle. Errors that
// already carry a code, and the "nothing newer" sentinel, pass through.
func TagVerify(err error) error {
	if err == nil {
		return nil
	}
	var coded *CodedError
	if errors.As(err, &coded) || errors.Is(err, feedsign.ErrKeySetRollback) {
		return err
	}
	m := strings.ToLower(err.Error())
	switch {
	case strings.Contains(m, "expired"), strings.Contains(m, "not valid at"):
		return Tag(CodeExpired, nil, err)
	case strings.Contains(m, "signature"), strings.Contains(m, "signed by root"),
		strings.Contains(m, "root_public_key"), strings.Contains(m, "envelope"), strings.Contains(m, "payload type"):
		return Tag(CodeSignatureInvalid, nil, err)
	}
	return Tag(CodeBundleInvalid, nil, err)
}
