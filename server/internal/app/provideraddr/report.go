package provideraddr

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	pa "github.com/openctemio/openctem/server/pkg/domain/provideraddr"
)

// severityOrder is the order findings are listed in.
var severityOrder = []string{"critical", "high", "medium", "low", "info", "none", ""}

// Format renders a report as plain text for an operator. It names no other
// organization and no asset: counts only.
func Format(r *Report) string {
	var b strings.Builder
	title := map[pa.Mode]string{pa.ModeDryRun: "dry run (nothing changed)", pa.ModeApply: "apply", pa.ModeRestore: "restore"}[r.Mode]
	fmt.Fprintf(&b, "provider-addresses %s\n", title)
	fmt.Fprintf(&b, "  organization   %s\n", r.TenantID)
	fmt.Fprintf(&b, "  dataset        %s (job version %d)\n", r.DatasetVersion, r.JobVersion)
	run := r.RunID
	if r.Resumed {
		run += " (resumed)"
	}
	fmt.Fprintf(&b, "  run            %s\n", run)
	state := "finished"
	if !r.Completed {
		state = "stopped early: run it again to continue"
	}
	fmt.Fprintf(&b, "  batches        %d, %d address assets read, %s, %s\n", r.Batches, r.Scanned, r.Duration, state)
	c := r.Counts
	if r.Mode == pa.ModeRestore {
		fmt.Fprintf(&b, "\n  Restored       %d\n  Changed since the move (left as they are) %d\n", c[pa.CountRestored], c[pa.CountChanged])
		return b.String()
	}

	fmt.Fprintf(&b, "\nAddresses inside published shared ranges: %d\n", c[pa.CountAddresses])
	type row struct {
		provider string
		bucket   pa.Bucket
		n        int
	}
	var rows []row
	for k, v := range c {
		if p, bk, ok := pa.ParseAddressKey(k); ok {
			rows = append(rows, row{p, bk, v})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].provider != rows[j].provider {
			return rows[i].provider < rows[j].provider
		}
		return rows[i].bucket < rows[j].bucket
	})
	if len(rows) > 0 {
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  provider\tgroup\taddresses")
		for _, x := range rows {
			fmt.Fprintf(tw, "  %s\t%s\t%d\n", x.provider, x.bucket, x.n)
		}
		_ = tw.Flush()
	}
	fmt.Fprintf(&b, "\nName-to-address links folded into the names' address history: %d (%d not yet in that history)\n",
		c[pa.CountEdgesFolded], c[pa.CountEdgesNotInHistory])
	fmt.Fprintf(&b, "Services moved from an address to their name: %d; certificates moved: %d\n",
		c[pa.CountServicesRelinked], c[pa.CountCertificatesRelinked])
	fmt.Fprintf(&b, "  findings on those services: %s\n", severities(c))
	fmt.Fprintf(&b, "Services named by the address (stay on the kept address): %d, findings on them: %d\n",
		c[pa.CountAddressServices], c[pa.CountAddressServiceFindings])
	if n := c[pa.CountNameServicesWithoutName]; n > 0 {
		fmt.Fprintf(&b, "Services named by a host that is not an asset (address kept): %d\n", n)
	}
	fmt.Fprintf(&b, "Addresses archived: %d; kept: %d; attribution set to dependency: %d\n",
		c[pa.CountArchived], c[pa.CountKept], c[pa.CountAttributionSet])
	fmt.Fprintf(&b, "Skipped (target of a queued or running scan, next pass): %d\n", c[pa.CountSkippedActiveRun])
	fmt.Fprintf(&b, "Restored because their range left the dataset: %d\n", c[pa.CountReclassified])
	fmt.Fprintf(&b, "Edges deleted (journaled): %d; edges added: %d; journal items: %d\n",
		c[pa.CountEdgesDeleted], c[pa.CountEdgesAdded], c[pa.CountItemsJournaled])
	fmt.Fprintf(&b, "Scope entries for the scope card: %d exact, %d ranges inside a shared range%s\n",
		c[pa.CountCardEntriesExact], c[pa.CountCardEntriesRange], cardOrigins(c))
	fmt.Fprintf(&b, "Inventory total: %d before, %d after\n", c[pa.CountInventoryBefore], c[pa.CountInventoryAfterExpected])
	fmt.Fprintf(&b, "Finding status changes: %d\n", c[pa.CountFindingStatusChanges])
	if r.NoticeSent {
		fmt.Fprintln(&b, "Organization notice posted.")
	}
	return b.String()
}

func severities(c pa.Counts) string {
	got := map[string]int{}
	for k, v := range c {
		if s, ok := pa.ParseSeverityKey(k); ok {
			got[s] = v
		}
	}
	parts := make([]string, 0, len(got))
	for _, s := range severityOrder {
		if n, ok := got[s]; ok {
			label := s
			if label == "" {
				label = "unset"
			}
			parts = append(parts, fmt.Sprintf("%s %d", label, n))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func cardOrigins(c pa.Counts) string {
	var parts []string
	for k, v := range c {
		if kind, origin, ok := pa.ParseCardEntryKey(k); ok {
			parts = append(parts, fmt.Sprintf("%s %s %d", kind, origin, v))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return " (" + strings.Join(parts, ", ") + ")"
}
