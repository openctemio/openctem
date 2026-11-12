package ingest

// Receipt items of findings taken out of a report before the finding
// processor saw them (docs/architecture/ingest-receipts.md, "Dispositions"):
// the ones the output-type binding held for review (or could not keep),
// and the ones the caller refused before ingest (protocol v2: no asset of
// the segment). Without these, the item log named only what the processor
// itself skipped, and every finding a run lost earlier left no trace on its
// receipt.

import (
	"sort"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
)

// addRefusedItems books the refused and held findings on the output's item
// log, within the receipt's cap. sent is the report before the binding took
// the held findings out (holds.findings are its indices).
func addRefusedItems(output *Output, sent *ctis.Report, holds *contractHolds, refused []ingestreceipt.Item) {
	for _, it := range refused {
		if len(output.Items) >= ingestreceipt.MaxActionsPerReceipt {
			return
		}
		output.Items = append(output.Items, it)
	}
	if holds == nil || sent == nil || len(holds.findings) == 0 {
		return
	}
	disp, reason, policy := ingestreceipt.DispositionQuarantined, ingestreceipt.ReasonHeldForReview, ingestreceipt.PolicyBinding
	if holds.lost {
		disp, reason, policy = ingestreceipt.DispositionRejected, ingestreceipt.ReasonQuarantineFull, ingestreceipt.PolicyQuarantine
	}
	idx := make([]int, 0, len(holds.findings))
	for i, held := range holds.findings {
		if held && i >= 0 && i < len(sent.Findings) {
			idx = append(idx, i)
		}
	}
	sort.Ints(idx)
	for _, i := range idx {
		addItem(output, sent, &sent.Findings[i], disp, reason, policy, nil)
	}
}

// refusedV2Items are the receipt items of the findings of a protocol v2
// segment that name no asset of it (resolveV2Assets refused them).
func refusedV2Items(r *ctis.Report, keptIdx []int) []ingestreceipt.Item {
	if r == nil || len(keptIdx) == len(r.Findings) {
		return nil
	}
	kept := make(map[int]bool, len(keptIdx))
	for _, i := range keptIdx {
		kept[i] = true
	}
	out := make([]ingestreceipt.Item, 0, len(r.Findings)-len(keptIdx))
	for i := range r.Findings {
		if kept[i] || len(out) >= ingestreceipt.MaxActionsPerReceipt {
			continue
		}
		out = append(out, receiptItem(r, &r.Findings[i], ingestreceipt.DispositionRejected, ingestreceipt.ReasonUnresolvedRef,
			ingestreceipt.PolicyValidation, nil, 0))
	}
	return out
}
