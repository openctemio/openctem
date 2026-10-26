package ingest

// Candidates of an import. A recon directory an organization imports names
// hosts that may not be its own (a third party's name in a link, a CDN
// address, a typo). The importer marks each host asset with
// properties.import_scope; the import service sets it from the
// organization's own scope (never from the file's say-so). An asset the
// import creates whose scope is anything but in_target is held as a
// candidate: not in the inventory, not selected by a scan, not probed until
// a person decides (the same hold an unsolicited sensor report gets).
//
// Threat model: the file is untrusted. It cannot make a host in scope (the
// property is overwritten by the import service before ingest), cannot
// release a candidate, and cannot demote an asset the organization already
// had: only assets this very ingest created are held.

import (
	"context"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PropImportScope is the asset property that carries the scope verdict of
// an imported host.
const PropImportScope = "import_scope"

// Import scope verdicts.
const (
	ImportScopeIn      = "in_target"
	ImportScopeOutside = "outside_target"
	ImportScopeUnknown = "unknown"
)

// ImportCandidateHolder records candidate attribution for the assets an
// import created (*easm.ScanStamper). Tenant-scoped in the store.
type ImportCandidateHolder interface {
	HoldImportCandidates(ctx context.Context, tenantID shared.ID, assets []ScannedAsset) error
}

// SetImportCandidateHolder wires the candidate hold of imports. Unwired, an
// import that creates a candidate reports an error on its output.
func (s *Service) SetImportCandidateHolder(h ImportCandidateHolder) { s.importCandidates = h }

// importCandidates lists the assets this ingest created whose report asset
// carries a scope verdict other than in_target.
func importCandidates(scope *alterScope, report *ctis.Report, assetMap map[string]shared.ID) []ScannedAsset {
	if scope == nil || report == nil {
		return nil
	}
	var out []ScannedAsset
	seen := map[shared.ID]bool{}
	for i := range report.Assets {
		a := &report.Assets[i]
		verdict, _ := a.Properties[PropImportScope].(string)
		if verdict == "" || verdict == ImportScopeIn {
			continue
		}
		id := assetMap[a.ID]
		if id.IsZero() || seen[id] {
			continue
		}
		s, ok := scope.seen[id]
		if !ok || !s.created {
			continue
		}
		seen[id] = true
		out = append(out, ScannedAsset{ID: id, Name: s.name, Type: s.typ, Created: true})
	}
	return out
}

// holdImportCandidates is fail-visible: a failure is logged and reported on
// the output, because an unheld candidate must not go unnoticed.
func (s *Service) holdImportCandidates(ctx context.Context, tenantID shared.ID, scope *alterScope, report *ctis.Report, assetMap map[string]shared.ID, output *Output) {
	cands := importCandidates(scope, report, assetMap)
	if len(cands) == 0 {
		return
	}
	if s.importCandidates == nil {
		addError(output, "imported candidates could not be held for review")
		return
	}
	if err := s.importCandidates.HoldImportCandidates(ctx, tenantID, cands); err != nil {
		s.logger.Warn("ingest: import candidates not held", "tenant_id", tenantID.String(), "assets", len(cands), "error", err)
		addError(output, "imported candidates could not be held for review")
	}
}
