package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// aliasStubRepo resolves configured former keys (RFC-043 §6) and records the
// tenant every lookup was made for.
type aliasStubRepo struct {
	stubFindingRepository
	aliases map[string]string
	err     error
	tenants []shared.ID
}

func (s *aliasStubRepo) ResolveFingerprintAliases(_ context.Context, tenantID shared.ID, fps []string) (map[string]string, error) {
	s.tenants = append(s.tenants, tenantID)
	if s.err != nil {
		return nil, s.err
	}
	out := map[string]string{}
	for _, fp := range fps {
		if cur, ok := s.aliases[fp]; ok {
			out[fp] = cur
		}
	}
	return out, nil
}

func twoNetFindingsReport() *ctis.Report {
	mk := func(port int) ctis.Finding {
		return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.SeverityHigh,
			RuleID: "CVE-2024-6387", AssetRef: "asset-ref",
			Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2024-6387"},
			Network:       &ctis.NetworkLocation{Port: port, Protocol: "tcp"}}
	}
	return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nessus"}, Findings: []ctis.Finding{mk(22), mk(2222)}}
}

// Two keys of one finding in one report are one observation: the former key
// is translated to the current one before the in-batch dedup.
func TestProcessBatch_FormerKeysFoldIntoTheirFinding(t *testing.T) {
	tenantID, assetID := shared.NewID(), shared.NewID()
	report := twoNetFindingsReport()
	k22, _ := generateFindingFingerprint(assetID, &report.Findings[0], report.Tool)
	k2222, _ := generateFindingFingerprint(assetID, &report.Findings[1], report.Tool)
	repo := &aliasStubRepo{aliases: map[string]string{k2222: k22}}
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())

	err := p.ProcessBatch(context.Background(), newTestSensor(t, tenantID), tenantID, report,
		map[string]shared.ID{"asset-ref": assetID}, branch.BranchTypeRules{}, &Output{}, map[string]shared.ID{})
	require.NoError(t, err)
	require.Len(t, repo.created, 1, "a former key and the current key of one finding are one observation")
	assert.Equal(t, k22, repo.created[0].Fingerprint())
	require.NotEmpty(t, repo.tenants)
	for _, tn := range repo.tenants {
		assert.Equal(t, tenantID, tn, "alias lookups are scoped to the report's tenant")
	}
}

// A failed lookup resolves nothing; the report is still ingested.
func TestProcessBatch_AliasLookupFailureIsNotFatal(t *testing.T) {
	tenantID, assetID := shared.NewID(), shared.NewID()
	repo := &aliasStubRepo{err: errors.New("db down")}
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())

	err := p.ProcessBatch(context.Background(), newTestSensor(t, tenantID), tenantID, twoNetFindingsReport(),
		map[string]shared.ID{"asset-ref": assetID}, branch.BranchTypeRules{}, &Output{}, map[string]shared.ID{})
	require.NoError(t, err)
	assert.Len(t, repo.created, 2)
}
