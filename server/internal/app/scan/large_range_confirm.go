package scan

// Large range confirmation: a scan whose direct targets name a range wider
// than a /16 is saved only when the request confirms it. Design:
// docs/rfcs/RFC-151-large-range-targets.md.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// CodeLargeRangeUnconfirmed: a create, edit or import names a range wider
// than a /16 without confirm_large_range: true.
const CodeLargeRangeUnconfirmed = "LARGE_RANGE_UNCONFIRMED"

// requireLargeRangeConfirmed refuses targets holding a range wider than a
// /16 unless confirmed. The message names the ranges, their address count
// and the most /16 chunks they are dispatched as, so an API or MCP caller
// sees what it is about to start before it confirms.
func requireLargeRangeConfirmed(targets []string, confirmed bool) error {
	if confirmed {
		return nil
	}
	var ranges []string
	var addresses, chunks uint64
	for _, t := range targets {
		r, ok := rangeTarget(strings.TrimSpace(t))
		if !ok {
			continue
		}
		n, full := r.Size()
		if !full && n <= MaxRangeAddresses {
			continue
		}
		ranges = append(ranges, strings.TrimSpace(t))
		if full {
			// Never validated this wide; counted as the bound so the
			// message stays finite.
			n = 1 << 63
		}
		addresses += n
		chunks += (n + MaxRangeAddresses - 1) / MaxRangeAddresses
	}
	if len(ranges) == 0 {
		return nil
	}
	return shared.NewDomainError(CodeLargeRangeUnconfirmed,
		fmt.Sprintf("%s: %s addresses, dispatched as up to %s /16 chunks and scanned live hosts first. Confirm the size with confirm_large_range: true.",
			strings.Join(ranges, ", "), groupDigits(addresses), groupDigits(chunks)),
		shared.ErrValidation).WithDetails(LargeRangeDetails{Ranges: ranges, Addresses: addresses, Chunks: chunks})
}

// LargeRangeDetails is the error body's details on LARGE_RANGE_UNCONFIRMED.
type LargeRangeDetails struct {
	Ranges    []string `json:"ranges"`
	Addresses uint64   `json:"addresses"`
	Chunks    uint64   `json:"chunks"`
}

// groupDigits writes n with comma thousands separators.
func groupDigits(n uint64) string {
	s := strconv.FormatUint(n, 10)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}
