package findingimport

// What a scan file proves closes (docs/architecture/finding-import.md, "What
// a Nessus import closes"). A file that carries its own coverage (a Nessus
// export: per host its scan end, whether the scan finished and logged in,
// and the plugins and families that ran) takes its close scope from its own
// hosts; the uploader declares nothing. An open finding of the file's tool
// on one of its hosts that the upload did not report closes only when the
// file proves it gone (importer.ImportCoverage.Covers): the file is
// complete, the host finished, the check ran there, a local check only where
// the scan logged in, never a compliance result by absence, never a finding
// seen after the host's scan. A compliance check the file reports as passed
// resolves the open failure of the same check on the same host.
//
// The guards of a full-coverage upload stay (coverage.go): the uploader
// needs findings:verify; critical and known-exploited findings, leaked
// secrets, human sources, branch occurrences and findings last seen by a
// platform sensor never close; the mass-close guard holds; nothing closes
// when any file or row of the upload failed. A close is dated when the file
// observed the host, not when it was uploaded, so a later file that saw the
// finding again reopens it, and an older file never closes what was seen
// after it. Every candidate gets exactly one outcome on the receipt
// (ingestreceipt.Closing).

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/ctis/v2/importer"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// fileCoverageRepo is implemented by the postgres finding repository.
type fileCoverageRepo interface {
	FileCoverageCandidates(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string, receiptID shared.ID) ([]vulnerability.FileCoverageCandidate, int, error)
	ResolveFileCoverage(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string, receiptID shared.ID, closes []vulnerability.TimedClose) ([]shared.ID, error)
	CompliancePassCandidates(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string, fingerprints []string) ([]vulnerability.FileCoverageCandidate, error)
	ResolveCompliancePassed(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string, closes []vulnerability.TimedClose) ([]shared.ID, error)
}

// fileOutcome is the decision for one candidate: a kept reason, or a close
// (reason Closed*) at the time the file observed the proof.
type fileOutcome struct {
	tool   string
	asset  shared.ID
	reason string
	close  bool
	at     time.Time
}

// toolScope is what one tool's files of the upload cover.
type toolScope struct {
	assets map[shared.ID]bool
	open   int
}

// hasFileCoverage reports whether a stored file of the upload carries its
// own coverage.
func hasFileCoverage(results []FileResult) bool {
	for _, fr := range results {
		if fr.Coverage != nil && fr.Ingest != nil && fr.Tool != "" {
			return true
		}
	}
	return false
}

// uploadIncomplete reports whether an upload proves nothing about what it
// left out: the request was cut short, it went through a mapping or a
// severity filter, a file failed, or a record was skipped or not stored.
func uploadIncomplete(req Request, results []FileResult, complete bool) bool {
	if !complete || req.Mapping != nil || req.MinSeverity != "" {
		return true
	}
	for _, fr := range results {
		if fr.Error != nil || fr.Stats.Skipped > 0 || fr.Ingest != nil && (len(fr.Ingest.FailedFindings) > 0 || fr.Ingest.ReceiptFailed) {
			return true
		}
		if bundleFormat(fr.Format) {
			return true
		}
	}
	return false
}

// closeByFileCoverage closes what the upload's files prove gone and returns
// the receipt's account of it and the coverage note; nil when no file
// carries its own coverage.
func (s *Service) closeByFileCoverage(ctx context.Context, req Request, results []FileResult, complete bool) (*ingestreceipt.Closing, string) {
	if req.DryRun || !hasFileCoverage(results) {
		return nil, ""
	}
	repo, ok := s.repo.(fileCoverageRepo)
	if !ok {
		return nil, ""
	}
	c := ingestreceipt.NewClosing()
	incomplete := uploadIncomplete(req, results, complete)
	proves := false
	outcomes := map[shared.ID]fileOutcome{}
	scopes := map[string]*toolScope{}
	note := noteResolved
	for _, fr := range results {
		if fr.Coverage == nil || fr.Ingest == nil || fr.Tool == "" {
			continue
		}
		fileIncomplete := incomplete || !fr.Coverage.Complete
		proves = proves || !fileIncomplete
		refs, err := s.hostAssets(ctx, req, fr, c)
		if err != nil {
			s.logger.Warn("finding import: file coverage scope", "tenant_id", req.TenantID.String(), "error", err)
			return c, noteError
		}
		ts := scopes[fr.Tool]
		if ts == nil {
			ts = &toolScope{assets: map[shared.ID]bool{}}
			scopes[fr.Tool] = ts
		}
		assets := make([]shared.ID, 0, len(refs))
		for id := range refs {
			assets = append(assets, id)
			ts.assets[id] = true
		}
		sort.Slice(assets, func(i, j int) bool { return assets[i].String() < assets[j].String() })
		cands, open, err := repo.FileCoverageCandidates(ctx, req.TenantID, assets, fr.Tool, req.ReceiptID)
		if errors.Is(err, ingestreport.ErrReceiptIncomplete) {
			// Past the action cap the receipt no longer lists everything
			// the upload reported: absence cannot be decided.
			note = noteIncomplete
			continue
		}
		if err != nil {
			s.logger.Warn("finding import: file coverage candidates", "tenant_id", req.TenantID.String(), "error", err)
			return c, noteError
		}
		ts.open += open
		for _, cand := range cands {
			o := classifyAbsent(fr.Coverage, refs[cand.AssetID], cand, fileIncomplete, req.Coverage.CanVerify)
			o.tool, o.asset = fr.Tool, cand.AssetID
			merge(outcomes, cand.ID, o)
		}
		if err := s.classifyPassed(ctx, req, fr, repo, incomplete, outcomes); err != nil {
			s.logger.Warn("finding import: compliance passes", "tenant_id", req.TenantID.String(), "error", err)
			return c, noteError
		}
	}
	c.Considered = len(outcomes)
	held, proposed, closed := s.applyFileOutcomes(ctx, req, repo, outcomes, scopes, c)
	switch {
	case !proves:
		// Nothing the upload holds proves an absence: the receipt stays
		// partial; Closing says why (file_incomplete).
		note = noteIncomplete
	case !req.Coverage.CanVerify:
		note = noteNeedsVerify
	case held:
		note = noteHeld
	case proposed > 0 && closed == 0:
		note = noteProposed
	}
	return c, note
}

// hostAssets maps the persisted asset of each host of the file, in the
// uploader's scope, to the host records naming it, and counts the hosts.
func (s *Service) hostAssets(ctx context.Context, req Request, fr FileResult, c *ingestreceipt.Closing) (map[shared.ID][]importer.HostCoverage, error) {
	refs := map[shared.ID][]importer.HostCoverage{}
	ids := make([]shared.ID, 0, len(fr.Coverage.Hosts))
	for _, h := range fr.Coverage.Hosts {
		c.Hosts++
		if !h.Finished || h.ObservedAt == nil {
			c.HostsUnfinished++
		}
		if !h.LocalChecks {
			c.HostsLocalChecksFailed++
		}
		id, ok := fr.Ingest.AssetMap[h.AssetRef]
		if !ok || id.IsZero() {
			continue
		}
		if _, seen := refs[id]; !seen {
			ids = append(ids, id)
		}
		refs[id] = append(refs[id], h)
	}
	if scope := req.coverageScope(); scope != nil && len(ids) > 0 {
		in, err := scope.AssetsInScope(ctx, ids)
		if err != nil {
			return nil, err
		}
		keep := map[shared.ID]bool{}
		for _, id := range in {
			keep[id] = true
		}
		for id := range refs {
			if !keep[id] {
				delete(refs, id)
			}
		}
	}
	return refs, nil
}

// isLocalCheck reports whether a check reads the host from inside (it can
// only run where the scan logged in).
func isLocalCheck(cand vulnerability.FileCoverageCandidate) bool {
	return importer.IsLocalFamily(cand.Family) || strings.EqualFold(strings.TrimSpace(cand.PluginType), "local")
}

// classifyAbsent decides an open finding the file did not report. Every
// host record naming its asset must prove the absence.
func classifyAbsent(cov *importer.ImportCoverage, hosts []importer.HostCoverage, cand vulnerability.FileCoverageCandidate,
	incomplete, canVerify bool) fileOutcome {
	kept := func(r string) fileOutcome { return fileOutcome{reason: r} }
	if incomplete || cov == nil || !cov.Complete || len(hosts) == 0 {
		return kept(ingestreceipt.KeptFileIncomplete)
	}
	var at time.Time
	for _, h := range hosts {
		if !h.Finished || h.ObservedAt == nil {
			return kept(ingestreceipt.KeptHostNotFinished)
		}
		if at.IsZero() || h.ObservedAt.Before(at) {
			at = *h.ObservedAt
		}
	}
	if cand.LastSeenAt.After(at) {
		return kept(ingestreceipt.KeptSeenLater)
	}
	if cand.Compliance {
		// Only a passed result of the same check resolves a compliance
		// failure, never its absence.
		return kept(ingestreceipt.KeptGuard)
	}
	local := isLocalCheck(cand)
	for _, h := range hosts {
		if local && !h.LocalChecks {
			return kept(ingestreceipt.KeptLocalChecksNotRun)
		}
	}
	seen := cand.LastSeenAt
	for _, h := range hosts {
		if !cov.Covers(h.AssetRef, cand.PluginID, cand.Family, local, false, &seen) {
			return kept(ingestreceipt.KeptCheckNotRun)
		}
	}
	if !cand.Closeable {
		return kept(ingestreceipt.KeptGuard)
	}
	if !canVerify {
		return kept(ingestreceipt.KeptNeedsVerify)
	}
	return fileOutcome{reason: ingestreceipt.ClosedNotInScan, close: true, at: at}
}

// classifyPassed decides the open compliance failures whose check the file
// reports as passed.
func (s *Service) classifyPassed(ctx context.Context, req Request, fr FileResult, repo fileCoverageRepo, incomplete bool,
	outcomes map[shared.ID]fileOutcome) error {
	passes := fr.Ingest.CompliancePassed
	if len(passes) == 0 {
		return nil
	}
	at := map[string]time.Time{}
	ids := make([]shared.ID, 0, len(passes))
	seenAsset := map[shared.ID]bool{}
	for _, p := range passes {
		if prev, ok := at[p.Fingerprint]; !ok || p.ObservedAt.After(prev) {
			at[p.Fingerprint] = p.ObservedAt
		}
		if !p.AssetID.IsZero() && !seenAsset[p.AssetID] {
			seenAsset[p.AssetID] = true
			ids = append(ids, p.AssetID)
		}
	}
	if scope := req.coverageScope(); scope != nil && len(ids) > 0 {
		in, err := scope.AssetsInScope(ctx, ids)
		if err != nil {
			return err
		}
		ids = in
	}
	fps := make([]string, 0, len(at))
	for fp := range at {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	cands, err := repo.CompliancePassCandidates(ctx, req.TenantID, ids, fr.Tool, fps)
	if err != nil {
		return err
	}
	for _, cand := range cands {
		o := fileOutcome{tool: fr.Tool, asset: cand.AssetID}
		t := at[cand.Fingerprint]
		switch {
		case incomplete:
			o.reason = ingestreceipt.KeptFileIncomplete
		case cand.LastSeenAt.After(t):
			o.reason = ingestreceipt.KeptSeenLater
		case !cand.Closeable:
			o.reason = ingestreceipt.KeptGuard
		case !req.Coverage.CanVerify:
			o.reason = ingestreceipt.KeptNeedsVerify
		default:
			o.reason, o.close, o.at = ingestreceipt.ClosedCompliancePassed, true, t
		}
		merge(outcomes, cand.ID, o)
	}
	return nil
}

// merge keeps one outcome per finding: a close wins over a kept reason (a
// second file of the upload proved what the first could not); between two
// closes, the earlier observation (the weaker claim).
func merge(outcomes map[shared.ID]fileOutcome, id shared.ID, o fileOutcome) {
	prev, ok := outcomes[id]
	switch {
	case !ok, o.close && !prev.close:
		outcomes[id] = o
	case o.close && prev.close && o.at.Before(prev.at):
		outcomes[id] = o
	}
}

// applyFileOutcomes counts the kept findings, sends the closes through the
// organization's closing mode and the mass-close guard, closes or proposes
// them, and records the closes on the receipt.
func (s *Service) applyFileOutcomes(ctx context.Context, req Request, repo fileCoverageRepo, outcomes map[shared.ID]fileOutcome,
	scopes map[string]*toolScope, c *ingestreceipt.Closing) (held bool, proposed, closedN int) {
	type key struct{ tool, reason string }
	groups := map[key][]vulnerability.TimedClose{}
	for id, o := range outcomes {
		if !o.close {
			c.Kept[o.reason]++
			continue
		}
		groups[key{o.tool, o.reason}] = append(groups[key{o.tool, o.reason}], vulnerability.TimedClose{ID: id, At: o.at})
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].tool != keys[j].tool {
			return keys[i].tool < keys[j].tool
		}
		return keys[i].reason < keys[j].reason
	})
	rec, _ := s.receipts.(receiptRecorder)
	for _, k := range keys {
		items := groups[k]
		byID := make(map[shared.ID]vulnerability.TimedClose, len(items))
		ids := make([]shared.ID, 0, len(items))
		for _, it := range items {
			byID[it.ID] = it
			ids = append(ids, it.ID)
		}
		toClose, propose, keep := s.closureDecider().Split(ctx, req.TenantID, ids, vulnerability.ClosureMethodCoveredScan)
		c.Kept[ingestreceipt.KeptGuard] += len(keep)
		ts := scopes[k.tool]
		if k.reason == ingestreceipt.ClosedNotInScan && ts != nil && len(toClose) > 0 &&
			ingest.DefaultBlindingGuard().Holds(len(ids), ts.open) {
			// A held run closes nothing; a person decides in Ready to close.
			propose = append(propose, toClose...)
			toClose = nil
			held = true
		}
		if len(propose) > 0 {
			s.proposeFileClosures(ctx, req, k.tool, k.reason, pick(byID, propose))
			c.Proposed += len(propose)
			proposed += len(propose)
		}
		if len(toClose) == 0 {
			continue
		}
		var assets []shared.ID
		if ts != nil {
			for id := range ts.assets {
				assets = append(assets, id)
			}
		}
		var closed []shared.ID
		var err error
		if k.reason == ingestreceipt.ClosedCompliancePassed {
			// The assets of the failures themselves (already in the
			// uploader's scope); the write re-checks them.
			assets = assets[:0]
			seen := map[shared.ID]bool{}
			for _, id := range toClose {
				if a := outcomes[id].asset; !a.IsZero() && !seen[a] {
					seen[a] = true
					assets = append(assets, a)
				}
			}
			closed, err = repo.ResolveCompliancePassed(ctx, req.TenantID, assets, k.tool, pick(byID, toClose))
		} else {
			closed, err = repo.ResolveFileCoverage(ctx, req.TenantID, assets, k.tool, req.ReceiptID, pick(byID, toClose))
		}
		if err != nil {
			s.logger.Warn("finding import: file coverage resolve", "tenant_id", req.TenantID.String(), "error", err)
		}
		// A finding someone changed meanwhile (or a failed write) stays open.
		c.Kept[ingestreceipt.KeptGuard] += len(toClose) - len(closed)
		c.Closed[k.reason] += len(closed)
		closedN += len(closed)
		if len(closed) > 0 && rec != nil {
			if _, err := rec.Record(ctx, &ingestreceipt.Delta{TenantID: req.TenantID, Tool: k.tool, Closed: closed,
				Source: ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: req.ReceiptID.String()}}); err != nil {
				s.logger.Warn("finding import: record closed findings", "tenant_id", req.TenantID.String(), "error", err)
			}
		}
	}
	return held, proposed, closedN
}

func pick(byID map[shared.ID]vulnerability.TimedClose, ids []shared.ID) []vulnerability.TimedClose {
	out := make([]vulnerability.TimedClose, 0, len(ids))
	for _, id := range ids {
		if it, ok := byID[id]; ok {
			out = append(out, it)
		}
	}
	return out
}

// proposeFileClosures records a Ready to close proposal for each finding,
// with the file's observation as evidence and its time.
func (s *Service) proposeFileClosures(ctx context.Context, req Request, tool, reason string, items []vulnerability.TimedClose) {
	recs := make([]vulnerability.ClosureProposalRecord, len(items))
	for i, it := range items {
		recs[i] = vulnerability.ClosureProposalRecord{FindingID: it.ID, Method: vulnerability.ClosureMethodCoveredScan,
			Evidence: map[string]any{"source": "scan_file_import", "receipt_id": req.ReceiptID.String(), "tool": tool,
				"reason": reason, "observed_at": it.At.UTC().Format(time.RFC3339)},
			EvidenceAt: it.At}
	}
	s.closureDecider().Record(ctx, req.TenantID, recs)
}
