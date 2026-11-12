package handler

// Practice counts of the findings list's practice switch
// (docs/architecture/finding-practices.md): GET /findings answers them with
// its page when asked with include=practice_counts, so the switch costs the
// page no request of its own.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/openctemio/openctem/server/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// includePracticeCounts is the include value of GET /findings that adds
// practice_counts to the page.
const includePracticeCounts = "practice_counts"

// FindingPracticeCountResponse is one practice with the caller's count.
type FindingPracticeCountResponse struct {
	// Practice: aspm, infra, external, cloud, compliance, offensive,
	// identity, runtime or other.
	Practice string `json:"practice"`
	Count    int64  `json:"count"`
}

// FindingPracticeCountsResponse is practice_counts of GET /findings.
type FindingPracticeCountsResponse struct {
	// Total is every finding the filter selects, whatever its practice.
	Total int64 `json:"total"`
	// Vulnerabilities is every practice except compliance (the list's default).
	Vulnerabilities int64 `json:"vulnerabilities"`
	// Practices lists every practice in display order, with its count.
	Practices []FindingPracticeCountResponse `json:"practices"`
	AsOf      time.Time                      `json:"as_of"`
}

// FindingListResponse is GET /findings (and POST /findings/search).
type FindingListResponse struct {
	ListResponse[FindingResponse]
	// PracticeCounts is present with include=practice_counts: the list's
	// filter with its practice condition left out, counted per practice for
	// the same caller (tenant, data scope and pentest membership applied).
	PracticeCounts *FindingPracticeCountsResponse `json:"practice_counts,omitempty"`
}

// findingListIncludes takes the include param out of q (it is a response
// option, not a filter field) and reports whether it asks for the practice
// counts. Any other value is 400 INVALID_FILTER naming it, so a typo is never
// answered as if it were understood.
func findingListIncludes(w http.ResponseWriter, q url.Values) (practiceCounts, ok bool) {
	raw, present := q["include"]
	if !present {
		return false, true
	}
	q.Del("include")
	for _, v := range raw {
		for _, part := range parseQueryArray(v) {
			if part != includePracticeCounts {
				filterquery.WriteError(w, &filterspec.Error{Details: []filterspec.Detail{{
					Param: "include", Reason: "must be: " + includePracticeCounts, Value: part,
				}}})
				return false, false
			}
			practiceCounts = true
		}
	}
	return practiceCounts, true
}

// listPracticeCounts counts the caller's findings per practice under spec
// with its practice condition removed. The counts are an aid beside the
// list: when they run out of time or fail, the page still answers without
// them (logged) and the switch shows no numbers.
func (h *VulnerabilityHandler) listPracticeCounts(ctx context.Context, r *http.Request, spec *filterspec.Spec) *FindingPracticeCountsResponse {
	counts, err := h.service.CountPractices(ctx, filterCaller(r), spec)
	if err != nil {
		if errors.Is(err, vulnerability.ErrFindingCountTimeout) {
			h.logger.Warn("findings practice counts timed out; list answered without them")
			return nil
		}
		h.logger.Error("failed to count findings per practice", "error", logger.SanitizeError(err))
		return nil
	}
	resp := &FindingPracticeCountsResponse{Total: counts.Total, AsOf: time.Now().UTC()}
	for _, p := range vulnerability.AllPractices() {
		n := counts.ByPractice[p]
		resp.Practices = append(resp.Practices, FindingPracticeCountResponse{Practice: p.String(), Count: n})
		if p != vulnerability.PracticeCompliance {
			resp.Vulnerabilities += n
		}
	}
	return resp
}
