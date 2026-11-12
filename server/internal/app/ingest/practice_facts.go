package ingest

import (
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// The practice of a new finding (docs/architecture/finding-practices.md)
// reads two facts of its asset: the stored type and whether it is
// internet-facing. The asset processor already holds every asset the
// report's findings land on, so it records those facts here and the
// findings processor attaches them to the findings it inserts: the insert
// then reads no asset (one statement less per report).

// notePracticeFacts records on output the practice facts of the assets the
// report assets landed on (assetMap). held are the entities this batch
// holds: an existing asset was read from the tenant's rows and merged under
// the upsert's own rules (the type is kept, the exposure filled only while
// unknown, internet access only ever set), a new one is the row inserted.
// An entity that is not the stored row (a create that lost a concurrent
// race, a row the database refused) is left out, as is an entity of another
// tenant; the insert reads the facts of those findings' assets itself.
func notePracticeFacts(output *Output, tenantID shared.ID, held []*asset.Asset,
	persisted map[string]shared.ID, isNew map[string]bool, assetMap map[string]shared.ID,
) {
	if output == nil || len(held) == 0 {
		return
	}
	mapped := make(map[shared.ID]bool, len(assetMap))
	for _, id := range assetMap {
		mapped[id] = true
	}
	for _, a := range held {
		if a == nil || !a.TenantID().Equals(tenantID) || !mapped[a.ID()] {
			continue
		}
		if persisted != nil {
			pid, ok := persisted[a.Name()]
			if ok && !pid.Equals(a.ID()) {
				continue // another row holds the name: the stored row is not this entity
			}
			if !ok && isNew[a.ID().String()] {
				continue // refused by the database: never stored
			}
		}
		if output.practiceFacts == nil {
			output.practiceFacts = make(map[shared.ID]vulnerability.PracticeAssetFacts)
		}
		output.practiceFacts[a.ID()] = vulnerability.PracticeAssetFactsOf(a)
	}
}

// attachPracticeFacts attaches the recorded facts of each finding's asset.
// Only the batch tenant's findings take them; any other finding, and one on
// an asset without recorded facts, is derived from the facts the insert
// reads (tenant-pinned).
func attachPracticeFacts(findings []*vulnerability.Finding, tenantID shared.ID, output *Output) {
	if output == nil || len(output.practiceFacts) == 0 {
		return
	}
	for _, f := range findings {
		if f == nil || !f.TenantID().Equals(tenantID) {
			continue
		}
		if facts, ok := output.practiceFacts[f.AssetID()]; ok {
			f.AttachPracticeAssetFacts(facts)
		}
	}
}
