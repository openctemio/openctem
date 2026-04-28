package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

type fakeVulnRepo struct {
	vulnerability.VulnerabilityRepository
	batchCalls int
	lastBatch  []*vulnerability.Vulnerability
	batchErr   error
	idFor      map[string]shared.ID
}

func (f *fakeVulnRepo) UpsertBatchByCVE(_ context.Context, vulns []*vulnerability.Vulnerability) error {
	f.batchCalls++
	f.lastBatch = vulns
	if f.batchErr != nil {
		return f.batchErr
	}
	for _, v := range vulns {
		if id, ok := f.idFor[v.CVEID()]; ok {
			v.SetID(id)
		} else {
			id := shared.NewID()
			f.idFor[v.CVEID()] = id
			v.SetID(id)
		}
	}
	return nil
}

func newFakeRepo() *fakeVulnRepo {
	return &fakeVulnRepo{idFor: map[string]shared.ID{}}
}

func TestCVEProcessor_EmptyReport(t *testing.T) {
	repo := newFakeRepo()
	p := NewCVEProcessor(repo, logger.NewDefault())
	output := &Output{}

	m, err := p.ProcessBatch(context.Background(), &ctis.Report{}, output)
	require.NoError(t, err)
	assert.Empty(t, m)
	assert.Equal(t, 0, repo.batchCalls)
}

func TestCVEProcessor_DedupesCVEsAcrossFindings(t *testing.T) {
	repo := newFakeRepo()
	p := NewCVEProcessor(repo, logger.NewDefault())
	report := &ctis.Report{
		Findings: []ctis.Finding{
			{Severity: ctis.SeverityHigh, Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2099-2001"}},
			{Severity: ctis.SeverityMedium, Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2099-2001"}},
			{Severity: ctis.SeverityCritical, Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2099-2002"}},
		},
	}
	output := &Output{}

	m, err := p.ProcessBatch(context.Background(), report, output)
	require.NoError(t, err)
	assert.Len(t, m, 2)
	assert.Contains(t, m, "CVE-2099-2001")
	assert.Contains(t, m, "CVE-2099-2002")
	require.Equal(t, 1, repo.batchCalls)
	require.Len(t, repo.lastBatch, 2)
}

func TestCVEProcessor_MergesSeverityAsMax(t *testing.T) {
	repo := newFakeRepo()
	p := NewCVEProcessor(repo, logger.NewDefault())
	report := &ctis.Report{
		Findings: []ctis.Finding{
			{Severity: ctis.SeverityLow, Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2099-2010"}},
			{Severity: ctis.SeverityCritical, Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2099-2010"}},
		},
	}
	output := &Output{}
	_, err := p.ProcessBatch(context.Background(), report, output)
	require.NoError(t, err)

	require.Len(t, repo.lastBatch, 1)
	assert.Equal(t, vulnerability.SeverityCritical, repo.lastBatch[0].Severity())
}

func TestCVEProcessor_SkipsInvalidCVEIDs(t *testing.T) {
	repo := newFakeRepo()
	p := NewCVEProcessor(repo, logger.NewDefault())
	report := &ctis.Report{
		Findings: []ctis.Finding{
			{Vulnerability: &ctis.VulnerabilityDetails{CVEID: ""}},
			{Vulnerability: &ctis.VulnerabilityDetails{CVEID: "not-a-cve"}},
			{Vulnerability: nil},
			{Severity: ctis.SeverityHigh, Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2099-2020"}},
		},
	}
	output := &Output{}
	m, err := p.ProcessBatch(context.Background(), report, output)
	require.NoError(t, err)
	assert.Len(t, m, 1)
	assert.Contains(t, m, "CVE-2099-2020")
	require.Len(t, repo.lastBatch, 1)
}

func TestCVEProcessor_RepoErrorReturnsEmptyMap(t *testing.T) {
	repo := newFakeRepo()
	repo.batchErr = errors.New("db down")
	p := NewCVEProcessor(repo, logger.NewDefault())
	report := &ctis.Report{
		Findings: []ctis.Finding{
			{Severity: ctis.SeverityHigh, Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2099-2030"}},
		},
	}
	output := &Output{}
	m, err := p.ProcessBatch(context.Background(), report, output)
	require.Error(t, err)
	assert.Empty(t, m)
}
