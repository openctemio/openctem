// Package privatedestinations is the platform console setting "Private
// network destinations": the private (RFC 1918 / ULA) ranges the platform's
// outbound requests may reach, beside the ranges set on the server with
// OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS.
//
// The setting opens the platform's own network to every organization (a
// webhook, an integration or a CI issuer of any tenant can then reach the
// opened addresses), so only a platform administrator holding the network
// permission changes it, with a fresh step-up and a reason; every change is
// audited critical with the old and new lists and told to every
// administrator. The guard (pkg/httpsec) reads the ranges from an atomic
// snapshot: the replica that saves applies the list at once, the others
// within RefreshInterval. Hard-blocked ranges (loopback, link-local and cloud
// metadata, ...) can never be opened.
//
// Design: docs/architecture/outbound-requests.md.
package privatedestinations

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/server/pkg/httpsec"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "network.private_destinations"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.private_destinations_changed"

// RefreshInterval is how often every replica reloads the setting into the
// guard (the console store's cache bound).
const RefreshInterval = consolesetting.CacheTTL

// Path is the console route of a change (audit).
const Path = "/api/v1/admin/settings/private-destinations"

// ErrOpenSignup refuses opening a range where anyone may create an
// organization (SIGNUP_MODE=open): the ranges would reach strangers'
// integrations. The same rule refuses OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS
// at start-up.
var ErrOpenSignup = errors.New("private ranges cannot be opened while anyone may create an organization (SIGNUP_MODE=open)")

// ErrNoActor refuses a change without an administrator.
var ErrNoActor = errors.New("a private destinations change needs an administrator")

// Entry is one opened range and its optional note ("GitLab").
type Entry struct {
	CIDR string `json:"cidr"`
	Note string `json:"note,omitempty"`
}

type stored struct {
	Ranges []Entry `json:"ranges"`
}

// RangeView is a console range as the console shows it.
type RangeView struct {
	Entry
	// Wide: wider than /24 (IPv4) or /64 (IPv6).
	Wide bool
}

// View is the setting as the console shows it.
type View struct {
	// Server are the ranges of OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS (read
	// only here).
	Server []RangeView
	// Console are the stored console ranges.
	Console []RangeView
	// InForce are the console ranges this replica's guard applies now.
	InForce []string
	// AllPrivateOpen: the development switch opens every private range.
	AllPrivateOpen bool
	// SignupOpen: SIGNUP_MODE=open; no console range can be opened.
	SignupOpen bool
	Meta       consolesetting.Meta
}

// Service reads, changes and applies the setting.
type Service struct {
	store    *consolesetting.Store[stored]
	recorder *consolesetting.Recorder
	log      *logger.Logger
	// apply installs a console list in the guard (httpsec in production).
	apply func([]string) error
	// applyMu orders a save's apply after a concurrent refresh's.
	applyMu sync.Mutex
	// generation counts saves on this server (guarded by applyMu). A refresh
	// that read the store before a save applies nothing: its copy is older
	// than the list the save applied.
	generation uint64
	// signupOpen: SIGNUP_MODE=open; no range is opened (Update refuses one,
	// Refresh applies none).
	signupOpen bool
}

// SetSignupOpen records SIGNUP_MODE=open.
func (s *Service) SetSignupOpen(open bool) { s.signupOpen = open }

// NewService creates the service.
func NewService(repo platformsetting.Repository, recorder *consolesetting.Recorder, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), recorder: recorder,
		log: log.With("component", "private_destinations"), apply: httpsec.SetConsolePrivateCIDRs}
}

// SetApplier replaces the guard hook (tests).
func (s *Service) SetApplier(f func([]string) error) { s.apply = f }

func rangeViews(entries []Entry) []RangeView {
	out := make([]RangeView, 0, len(entries))
	for _, e := range entries {
		v := RangeView{Entry: e}
		if _, n, err := net.ParseCIDR(e.CIDR); err == nil {
			v.Wide = httpsec.IsWideRange(n)
		}
		out = append(out, v)
	}
	return out
}

// Get returns the setting.
func (s *Service) Get(ctx context.Context) (View, error) {
	st, m, err := s.store.Fresh(ctx)
	if err != nil {
		return View{}, err
	}
	server := make([]Entry, 0)
	for _, c := range httpsec.AllowedPrivateCIDRs() {
		server = append(server, Entry{CIDR: c})
	}
	return View{Server: rangeViews(server), Console: rangeViews(st.Ranges), InForce: httpsec.ConsolePrivateCIDRs(),
		AllPrivateOpen: httpsec.AllowPrivate(), SignupOpen: s.signupOpen, Meta: m}, nil
}

// Canonical checks a console list and returns it in canonical form: every
// range valid (httpsec.ParseConsoleCIDR), no duplicates, at most
// httpsec.MaxConsolePrivateRanges, notes plain one-line text.
func Canonical(entries []Entry) ([]Entry, error) {
	raws := make([]string, 0, len(entries))
	for _, e := range entries {
		raws = append(raws, e.CIDR)
	}
	nets, err := httpsec.CanonicalConsoleCIDRs(raws)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(entries))
	for i, e := range entries {
		note := strings.TrimSpace(e.Note)
		if err := httpsec.CheckRangeNote(note); err != nil {
			return nil, &httpsec.RangeError{Index: i, Range: e.CIDR, Err: err}
		}
		out = append(out, Entry{CIDR: nets[i].String(), Note: note})
	}
	return out, nil
}

func cidrs(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.CIDR)
	}
	return out
}

// Update stores and applies the console list. The caller checked the
// administrator's permission and the fresh step-up. expectedVersion is the
// version read (0: nothing stored).
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, entries []Entry, reason string, expectedVersion int, ip, userAgent string) (View, error) {
	if actor == nil {
		return View{}, ErrNoActor
	}
	reason, err := consolesetting.CheckReason(reason)
	if err != nil {
		return View{}, err
	}
	next, err := Canonical(entries)
	if err != nil {
		return View{}, err
	}
	if s.signupOpen && len(next) > 0 {
		return View{}, ErrOpenSignup
	}
	prev, _, err := s.store.Fresh(ctx)
	if err != nil {
		// A broken stored value must still be replaceable.
		prev = stored{}
	}
	s.applyMu.Lock()
	if _, err := s.store.Put(ctx, stored{Ranges: next}, expectedVersion, actor.ID()); err != nil {
		s.applyMu.Unlock()
		return View{}, err
	}
	s.generation++
	if err := s.apply(cidrs(next)); err != nil {
		// Canonical accepted the list, so the guard cannot refuse it; the
		// stored value is reapplied on the next refresh either way.
		s.log.Error("private destinations stored but not applied", "error", logger.SanitizeError(err))
	}
	s.applyMu.Unlock()
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Private network destinations",
		Method: "PUT", Path: Path, Reason: reason, Critical: true, Notify: true,
		Details: map[string]any{"previous_ranges": entryDetails(prev.Ranges), "ranges": entryDetails(next),
			"server_ranges": httpsec.AllowedPrivateCIDRs()},
	}, ip, userAgent)
	return s.Get(ctx)
}

// entryDetails is a list for the audit row (never nil, so an empty list
// reads as [] rather than null).
func entryDetails(entries []Entry) []Entry {
	if entries == nil {
		return []Entry{}
	}
	return entries
}

// Refresh reloads the stored list into the guard. A stored value that no
// longer passes the checks opens nothing (fail closed); an unreadable store
// keeps the list in force (a database blip must not cut every private
// integration off, nor open anything new).
func (s *Service) Refresh(ctx context.Context) error {
	s.applyMu.Lock()
	gen := s.generation
	s.applyMu.Unlock()
	st, _, err := s.store.Fresh(ctx)
	if err != nil {
		return err
	}
	list, cerr := Canonical(st.Ranges)
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if s.generation != gen {
		// A save ran while this refresh read the store: the save's list is
		// newer, and the next refresh reads it again.
		return nil
	}
	if cerr != nil {
		s.log.Error("stored private destinations are invalid; no console range is open", "error", logger.SanitizeError(cerr))
		return s.apply(nil)
	}
	if s.signupOpen && len(list) > 0 {
		s.log.Error("stored private destinations are not applied: SIGNUP_MODE=open lets anyone create an organization")
		return s.apply(nil)
	}
	return s.apply(cidrs(list))
}

// Start applies the stored list now and then every RefreshInterval until
// ctx ends.
func (s *Service) Start(ctx context.Context) {
	s.refreshOnce(ctx)
	go func() {
		t := time.NewTicker(RefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.refreshOnce(ctx)
			}
		}
	}()
}

func (s *Service) refreshOnce(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.Refresh(rctx); err != nil && ctx.Err() == nil {
		s.log.Warn("private destinations refresh failed; keeping the ranges in force", "error", logger.SanitizeError(err))
	}
}

// Inspect resolves host and reports how the guard treats each address. It
// never connects.
func (s *Service) Inspect(ctx context.Context, host string) (*httpsec.DestinationReport, error) {
	return httpsec.InspectDestination(ctx, host)
}
