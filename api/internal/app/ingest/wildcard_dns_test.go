package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
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
			Reports: []ingestreport.CoverageReport{{State: protov2.StateCompleted, TouchedAssetIDs: []shared.ID{resolved.ID()}}}}
	}
	run := func(cmd *command.Command, cov *ingestreport.CommandCoverage, asTenant shared.ID) *wcStore {
		st := &wcStore{}
		s := &Service{commands: wcCommands{tenant: tenant, cmd: cmd}, assetRepo: assets, wildcardDNS: st, logger: logger.NewNop()}
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

	t.Run("an apex the resolver left out is cleared, never marked", func(t *testing.T) {
		apex := wcAsset(t, "example.com")
		withApex := wcAssets{tenant: tenant, byName: map[string]*asset.Asset{"example.com": apex, "guess.example.com": guess}}
		payload := map[string]any{"scanner": "dnsx", "targets": []string{"example.com", "guess.example.com"},
			"config": map[string]any{"wildcard_filter": true}}
		cmd := wcCommand(t, tenant, payload)
		st := &wcStore{}
		s := &Service{commands: wcCommands{tenant: tenant, cmd: cmd}, assetRepo: withApex, wildcardDNS: st, logger: logger.NewNop()}
		cov := &ingestreport.CommandCoverage{CommandStatus: string(command.CommandStatusCompleted),
			Reports: []ingestreport.CoverageReport{{State: protov2.StateCompleted}}}
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
