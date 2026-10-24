package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// defaultResolvedRepo is a finding repository whose only behavior is the
// default-branch lookup (the rest of the interface is never called here).
type defaultResolvedRepo struct {
	stubFindingRepository
	resolved map[string]bool
	err      error
}

func (r *defaultResolvedRepo) DefaultBranchResolvedFingerprints(_ context.Context, _ shared.ID, fps []string) (map[string]bool, error) {
	if r.err != nil {
		return nil, r.err
	}
	out := map[string]bool{}
	for _, fp := range fps {
		if r.resolved[fp] {
			out[fp] = true
		}
	}
	return out, nil
}

func branchReportProcessor(t *testing.T, repo *defaultResolvedRepo, def *branch.Branch) *FindingProcessor {
	t.Helper()
	return &FindingProcessor{repo: repo, branchRepo: &defaultBranchStubRepo{defaultBranch: def}, logger: logger.NewNop()}
}

func TestBranchRunDoesNotReopenDefaultBranchResolved(t *testing.T) {
	ctx := context.Background()
	assetID := shared.NewID()
	mainBranch, err := branch.NewBranch(assetID, "main", branch.TypeMain)
	require.NoError(t, err)
	prBranch := shared.NewID()
	mainID := mainBranch.ID()
	report := &ctis.Report{Metadata: ctis.ReportMetadata{Branch: &ctis.BranchInfo{Name: "feature/x"}}}
	findings := []branchSighting{{fingerprint: "resolved-on-main", assetID: assetID, branchID: &prBranch}, {fingerprint: "branch-only", assetID: assetID, branchID: &prBranch}}
	repo := &defaultResolvedRepo{resolved: map[string]bool{"resolved-on-main": true}}
	p := branchReportProcessor(t, repo, mainBranch)

	// PR/feature run: the default-branch finding is withheld, the branch-only one is not.
	out := &Output{}
	off := p.offDefaultBranchFingerprints(ctx, report, findings)
	kept := p.withoutDefaultBranchResolved(ctx, shared.NewID(), []string{"resolved-on-main", "branch-only"}, off, out)
	assert.Equal(t, []string{"branch-only"}, kept)
	assert.Equal(t, 1, out.ReopensWithheld)

	// Default-branch run: nothing is withheld, so the reopen proceeds.
	mainReport := &ctis.Report{Metadata: ctis.ReportMetadata{Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true}}}
	mainFindings := []branchSighting{{fingerprint: "resolved-on-main", assetID: assetID, branchID: &mainID}}
	out = &Output{}
	off = p.offDefaultBranchFingerprints(ctx, mainReport, mainFindings)
	assert.Empty(t, off)
	kept = p.withoutDefaultBranchResolved(ctx, shared.NewID(), []string{"resolved-on-main"}, off, out)
	assert.Equal(t, []string{"resolved-on-main"}, kept)
	assert.Zero(t, out.ReopensWithheld)
}

func TestBranchRunWithholdsWhenLookupFails(t *testing.T) {
	assetID := shared.NewID()
	mainBranch, err := branch.NewBranch(assetID, "main", branch.TypeMain)
	require.NoError(t, err)
	pr := shared.NewID()
	repo := &defaultResolvedRepo{err: errors.New("db down")}
	p := branchReportProcessor(t, repo, mainBranch)
	report := &ctis.Report{Metadata: ctis.ReportMetadata{Branch: &ctis.BranchInfo{Name: "pr-1"}}}
	off := p.offDefaultBranchFingerprints(context.Background(), report, []branchSighting{{fingerprint: "fp", assetID: assetID, branchID: &pr}})
	out := &Output{}
	assert.Empty(t, p.withoutDefaultBranchResolved(context.Background(), shared.NewID(), []string{"fp"}, off, out))
}

func TestRunWithoutBranchInfoIsNotABranchSighting(t *testing.T) {
	p := branchReportProcessor(t, &defaultResolvedRepo{}, nil)
	report := &ctis.Report{}
	assert.Empty(t, p.offDefaultBranchFingerprints(context.Background(), report, []branchSighting{{fingerprint: "fp", assetID: shared.NewID()}}))
}
