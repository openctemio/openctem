package retest

// Version re-check of a version-match finding
// (docs/architecture/finding-retest-strategy.md): the fingerprint that read
// the software version runs again on the asset (an ad-hoc scan through the
// scan service's target gates), its report updates the asset's software
// inventory, and the version seen since the retest started is evaluated
// against the CVE's affected ranges.

import (
	"context"
	"fmt"
	"strings"

	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// dispatchVersion starts the fingerprint scan and links its run to the
// retest (the run shows the scan's tasks and logs in Runs).
func (s *Service) dispatchVersion(ctx context.Context, rt *retestdom.Retest, c *candidate) error {
	if s.fingerprinter == nil {
		return fmt.Errorf("version re-check is not wired")
	}
	runID, err := s.fingerprinter.StartFingerprint(ctx, rt.TenantID, c.tool, c.target, rt.RequestedBy)
	if err != nil {
		return err
	}
	rt.RunID = &runID
	if l, ok := s.store.(runLinker); ok {
		if err := l.SetRun(ctx, rt.TenantID, rt.ID, runID); err != nil {
			s.logger.Warn("failed to link the retest to its fingerprint run", "retest_id", rt.ID.String(), "error", err)
		}
	}
	return nil
}

// trySettleVersion settles a version re-check once its fingerprint run ended
// (or the deadline passed). A run that ended with nothing observed waits
// ingestGrace for its report before it is settled.
func (s *Service) trySettleVersion(ctx context.Context, rt *retestdom.Retest, force bool) (bool, error) {
	if s.versions == nil {
		return s.settle(ctx, rt, retestdom.Inconclusive(retestdom.ReasonError, "the version re-check is not available"), s.now())
	}
	var run *scanrun.Run
	if rt.RunID != nil && s.runReader != nil {
		if r, err := s.runReader.GetByTenantAndID(ctx, rt.TenantID, *rt.RunID); err == nil {
			run = r
		}
	}
	ended := run == nil || run.Status.IsTerminal()
	if !ended && !force {
		return false, nil
	}
	link, err := s.versions.FindingLink(ctx, rt.TenantID, rt.FindingID)
	if err != nil {
		return false, err
	}
	if link == nil {
		return s.settle(ctx, rt, retestdom.Inconclusive(retestdom.ReasonVersionNotObserved,
			"the software this finding was matched on is no longer known"), s.now())
	}
	observed, err := s.versions.ObservedSince(ctx, rt.TenantID, link.AssetID, link.ProductID, link.Location, rt.CreatedAt)
	if err != nil {
		return false, err
	}
	checkedAt := s.now()
	if run != nil && run.CompletedAt != nil {
		checkedAt = *run.CompletedAt
	}
	if len(observed) == 0 && ended && !force && run != nil && s.now().Before(checkedAt.Add(ingestGrace)) {
		return false, nil
	}
	var ranges []softwarematch.AffectedRange
	if len(observed) > 0 && observed[0].VersionID != link.VersionID {
		if ranges, err = s.versions.RangesForProduct(ctx, link.ProductID); err != nil {
			return false, err
		}
	}
	v := DecideVersion(*link, rt.TemplateID, observed, ranges)
	if len(observed) == 0 && run != nil && run.Status.IsTerminal() &&
		run.Status != scanrun.RunStatusCompleted && run.Status != scanrun.RunStatusPartial {
		v = retestdom.Inconclusive(retestdom.ReasonError, fmt.Sprintf("the fingerprint scan ended %s", run.Status))
	}
	if !ended && len(observed) == 0 {
		v.Reason = "no fingerprint result before the deadline"
	}
	return s.settle(ctx, rt, v, checkedAt)
}

// DecideVersion turns what the fingerprint saw into a verdict:
//   - nothing seen: inconclusive (a version that is no longer shown is not
//     a fixed one);
//   - the finding's own version seen again: still vulnerable;
//   - another version that does not parse: inconclusive;
//   - another version still in one of the CVE's affected ranges: still
//     vulnerable, with the new version as evidence;
//   - another version outside every range: confirmed fixed.
//
// observed lists the current version first (ObservedSince); ranges are the
// product's ranges.
func DecideVersion(link softwarematch.FindingLink, cveID string, observed []softwarematch.ObservedVersion, ranges []softwarematch.AffectedRange) retestdom.Verdict {
	product := nonEmptyStr(link.Product, "the product")
	if len(observed) == 0 {
		return retestdom.Inconclusive(retestdom.ReasonVersionNotObserved,
			fmt.Sprintf("the fingerprint did not report %s on the asset; a version that is no longer shown is not proof of a fix", product))
	}
	cur := observed[0]
	if cur.VersionID == link.VersionID {
		return retestdom.Verdict{Outcome: retestdom.OutcomeStillVulnerable, Code: retestdom.ReasonVersionStillAffected,
			Reason: fmt.Sprintf("%s %s was detected again", product, nonEmptyStr(cur.Raw, link.Version))}
	}
	obs := vulnmatch.Observed{Version: cur.Raw, Scheme: cur.Scheme, Edition: cur.Edition}
	if _, ok := vulnmatch.ParseSchemeVersion(cur.Scheme, cur.Raw); !cur.Comparable || !cur.Scheme.Comparable() || !ok {
		return retestdom.Inconclusive(retestdom.ReasonVersionNotObserved,
			fmt.Sprintf("%s now reports version %q, which cannot be compared with the affected ranges", product, cur.Raw))
	}
	rs := make([]vulnmatch.Range, 0, len(ranges))
	for _, r := range ranges {
		rs = append(rs, r.Range)
	}
	for _, m := range vulnmatch.MatchVersion(obs, rs) {
		if strings.EqualFold(m.VulnID, cveID) {
			return retestdom.Verdict{Outcome: retestdom.OutcomeStillVulnerable, Code: retestdom.ReasonVersionStillAffected,
				Reason: fmt.Sprintf("%s now runs %s, still in the affected range %s of %s", product, cur.Raw, m.Range.Describe(), cveID)}
		}
	}
	return retestdom.Verdict{Outcome: retestdom.OutcomeConfirmedFixed, Code: retestdom.ReasonVersionNotAffected,
		Reason: fmt.Sprintf("%s now runs %s, outside the affected ranges of %s", product, cur.Raw, cveID)}
}
