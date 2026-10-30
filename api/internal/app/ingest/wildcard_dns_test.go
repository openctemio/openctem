package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetresolution"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type wcCommands struct {
	tenant shared.ID
	cmd    *command.Command
}

func (c wcCommands) GetByTenantAndID(_ context.Context, t, id shared.ID) (*command.Command, error) {
	if !t.Equals(c.tenant) || c.cmd == nil || c.cmd.ID != id {
		return nil, shared.ErrNotFound
	}
	return c.cmd, nil
}

type wcAssets struct {
	asset.Repository
	tenant shared.ID
	byName map[string]*asset.Asset
}

func (r wcAssets) GetByNames(_ context.Context, t shared.ID, names []string) (map[string]*asset.Asset, error) {
	out := map[string]*asset.Asset{}
	if !t.Equals(r.tenant) {
		return out, nil
	}
	for _, n := range names {
		if a, ok := r.byName[n]; ok {
			out[n] = a
		}
	}
	return out, nil
}

type wcStore struct {
	marked, cleared []shared.ID
}

func (s *wcStore) MarkWildcardOnly(_ context.Context, _ shared.ID, ids []shared.ID, _ shared.ID, _ time.Time) error {
	s.marked = append(s.marked, ids...)
	return nil
}

func (s *wcStore) ClearWildcardOnly(_ context.Context, _ shared.ID, ids []shared.ID) error {
	s.cleared = append(s.cleared, ids...)
	return nil
}

func (s *wcStore) WildcardOnly(context.Context, shared.ID, []shared.ID) (map[shared.ID]bool, error) {
	return nil, nil
}

// wcProber answers a fixed class per name.
type wcProber map[string]NameClass

func (p wcProber) Probe(_ context.Context, name string) NameClass { return p[name] }

// wcResolution records the resolution states written.
type wcResolution struct {
	failed, resolved []shared.ID
}

func (r *wcResolution) RecordResolved(_ context.Context, _ shared.ID, ids []shared.ID, _ time.Time) error {
	r.resolved = append(r.resolved, ids...)
	return nil
}

func (r *wcResolution) RecordFailed(_ context.Context, _ shared.ID, ids []shared.ID, _ time.Time, _ string) error {
	r.failed = append(r.failed, ids...)
	return nil
}

func (r *wcResolution) RecordFailedNames(context.Context, shared.ID, []string, time.Time, string) error {
	return nil
}

func (r *wcResolution) NotResolving(context.Context, shared.ID, []string) (map[string]bool, error) {
	return nil, nil
}

func (r *wcResolution) Get(context.Context, shared.ID, shared.ID) (*assetresolution.Resolution, error) {
	return nil, nil
}

func wcCommand(t *testing.T, tenant shared.ID, payload map[string]any) *command.Command {
	t.Helper()
	raw, _ := json.Marshal(payload)
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Complete(json.RawMessage(`{"exit_code":0}`))
	return cmd
}

func wcAsset(t *testing.T, name string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset(name, asset.AssetTypeSubdomain, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEvaluateWildcardDNS(t *testing.T) {
	tenant := shared.NewID()
	guess, resolved := wcAsset(t, "guess.example.com"), wcAsset(t, "api.example.com")
	assets := wcAssets{tenant: tenant, byName: map[string]*asset.Asset{"guess.example.com": guess, "api.example.com": resolved}}
	filtered := map[string]any{"scanner": "dnsx", "targets": []string{"Guess.example.com.", "api.example.com", "203.0.113.5"},
		"config": map[string]any{"wildcard_filter": true}}
	done := func() *ingestreport.CommandCoverage {
		return &ingestreport.CommandCoverage{CommandStatus: string(command.CommandStatusCompleted),
			Reports: []ingestreport.CoverageReport{{Integrity: protov2.IntegritySingle, State: protov2.StateCompleted, TouchedAssetIDs: []shared.ID{resolved.ID()}}}}
	}
	run := func(cmd *command.Command, cov *ingestreport.CommandCoverage, asTenant shared.ID) *wcStore {
		st := &wcStore{}
		s := &Service{commands: wcCommands{tenant: tenant, cmd: cmd}, assetRepo: assets, wildcardDNS: st, logger: logger.NewNop(),
			nameProber: wcProber{"guess.example.com": NameWildcardOnly}}
		s.evaluateWildcardDNS(context.Background(), asTenant, cmd.ID, cov)
		return st
	}

	t.Run("a filtered resolution marks what it did not report and clears what it did", func(t *testing.T) {
		st := run(wcCommand(t, tenant, filtered), done(), tenant)
		if len(st.marked) != 1 || st.marked[0] != guess.ID() {
			t.Fatalf("marked = %v, want the guess", st.marked)
		}
		if len(st.cleared) != 1 || st.cleared[0] != resolved.ID() {
			t.Fatalf("cleared = %v, want the reported name", st.cleared)
		}
	})

	probed := func(class NameClass) (*wcStore, *wcResolution) {
		st, res := &wcStore{}, &wcResolution{}
		cmd := wcCommand(t, tenant, filtered)
		s := &Service{commands: wcCommands{tenant: tenant, cmd: cmd}, assetRepo: assets, wildcardDNS: st, logger: logger.NewNop(),
			nameProber: wcProber{"guess.example.com": class}, resolutionStore: res}
		s.evaluateWildcardDNS(context.Background(), tenant, cmd.ID, done())
		return st, res
	}

	// The prod case: names with no DNS answer were marked wildcard-only.
	t.Run("a name with no DNS answer is not_resolving, never wildcard-only", func(t *testing.T) {
		st, res := probed(NameNoAnswer)
		if len(st.marked) != 0 {
			t.Fatalf("marked %v, want nothing", st.marked)
		}
		if len(res.failed) != 1 || res.failed[0] != guess.ID() {
			t.Fatalf("failed = %v, want the guess", res.failed)
		}
	})
	t.Run("a name that resolves by itself is not marked and any mark is cleared", func(t *testing.T) {
		st, res := probed(NameResolves)
		if len(st.marked) != 0 || len(res.failed) != 0 || len(res.resolved) != 1 {
			t.Fatalf("marked %v failed %v resolved %v", st.marked, res.failed, res.resolved)
		}
	})
	t.Run("an unsure probe changes nothing", func(t *testing.T) {
		st, res := probed(NameUnknown)
		if len(st.marked)+len(res.failed)+len(res.resolved) != 0 {
			t.Fatalf("marked %v failed %v resolved %v", st.marked, res.failed, res.resolved)
		}
	})
	t.Run("without a prober nothing is marked", func(t *testing.T) {
		st := &wcStore{}
		cmd := wcCommand(t, tenant, filtered)
		s := &Service{commands: wcCommands{tenant: tenant, cmd: cmd}, assetRepo: assets, wildcardDNS: st, logger: logger.NewNop()}
		s.evaluateWildcardDNS(context.Background(), tenant, cmd.ID, done())
		if len(st.marked) != 0 {
			t.Fatalf("marked %v", st.marked)
		}
	})

	t.Run("an apex the resolver left out is cleared, never marked", func(t *testing.T) {
		apex := wcAsset(t, "example.com")
		withApex := wcAssets{tenant: tenant, byName: map[string]*asset.Asset{"example.com": apex, "guess.example.com": guess}}
		payload := map[string]any{"scanner": "dnsx", "targets": []string{"example.com", "guess.example.com"},
			"config": map[string]any{"wildcard_filter": true}}
		cmd := wcCommand(t, tenant, payload)
		st := &wcStore{}
		s := &Service{commands: wcCommands{tenant: tenant, cmd: cmd}, assetRepo: withApex, wildcardDNS: st, logger: logger.NewNop(),
			nameProber: wcProber{"guess.example.com": NameWildcardOnly}, resolutionStore: &wcResolution{}}
		cov := &ingestreport.CommandCoverage{CommandStatus: string(command.CommandStatusCompleted),
			Reports: []ingestreport.CoverageReport{{Integrity: protov2.IntegritySingle, State: protov2.StateCompleted}}}
		s.evaluateWildcardDNS(context.Background(), tenant, cmd.ID, cov)
		if len(st.marked) != 1 || st.marked[0] != guess.ID() {
			t.Fatalf("marked = %v, want only the subdomain guess", st.marked)
		}
		if len(st.cleared) != 1 || st.cleared[0] != apex.ID() {
			t.Fatalf("cleared = %v, want the apex", st.cleared)
		}
	})

	for name, tc := range map[string]struct {
		payload map[string]any
		cov     func() *ingestreport.CommandCoverage
		tenant  shared.ID
	}{
		"filter off proves nothing": {map[string]any{"scanner": "dnsx", "targets": []string{"guess.example.com"},
			"config": map[string]any{"wildcard_filter": false}}, done, tenant},
		"filter unset proves nothing": {map[string]any{"scanner": "dnsx", "targets": []string{"guess.example.com"}}, done, tenant},
		"another tool": {map[string]any{"scanner": "httpx", "targets": []string{"guess.example.com"},
			"config": map[string]any{"wildcard_filter": true}}, done, tenant},
		"report still pending": {filtered, func() *ingestreport.CommandCoverage {
			c := done()
			c.Reports[0].State = protov2.StateProcessing
			return c
		}, tenant},
		"no report filed": {filtered, func() *ingestreport.CommandCoverage {
			c := done()
			c.Reports = nil
			return c
		}, tenant},
		"command failed": {filtered, func() *ingestreport.CommandCoverage {
			c := done()
			c.CommandStatus = string(command.CommandStatusFailed)
			return c
		}, tenant},
		"report items rejected": {filtered, func() *ingestreport.CommandCoverage {
			c := done()
			c.Reports[0].SegmentOutcomes = map[string]ingestreport.SegmentOutcome{"0": {RejectedAssets: 1}}
			return c
		}, tenant},
		"another tenant's command": {filtered, done, shared.NewID()},
	} {
		t.Run(name, func(t *testing.T) {
			st := run(wcCommand(t, tenant, tc.payload), tc.cov(), tc.tenant)
			if len(st.marked)+len(st.cleared) != 0 {
				t.Fatalf("marked %v cleared %v, want nothing", st.marked, st.cleared)
			}
		})
	}
}
