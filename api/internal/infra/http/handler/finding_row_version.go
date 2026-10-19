package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Optimistic concurrency on a finding's writes
// (docs/architecture/finding-row-version.md).

// CodeFindingChanged is the 409 code of a finding write refused because the
// finding changed since the caller read it.
const CodeFindingChanged apierror.Code = "FINDING_CHANGED"

// FindingIfMatch reads an If-Match header carrying the finding's row_version
// (`"7"`, `W/"7"` or `7`) on a single-finding write. The write is then refused
// with 409 FINDING_CHANGED unless the stored finding is still at that version,
// and the server does not retry it. Without the header the server writes on
// the version it reads itself (and retries a lost race). `*` is ignored.
func FindingIfMatch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get("If-Match"))
		if raw == "" || raw == "*" {
			next.ServeHTTP(w, r)
			return
		}
		version, ok := parseRowVersionTag(raw)
		if !ok {
			apierror.BadRequest("If-Match must be the finding's row_version").WriteJSON(w)
			return
		}
		id, err := shared.IDFromString(r.PathValue("id"))
		if err != nil {
			// The handler answers a malformed id.
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(vulnerability.WithExpectedRowVersion(r.Context(), id, version)))
	})
}

func parseRowVersionTag(raw string) (int64, bool) {
	raw = strings.TrimPrefix(raw, "W/")
	raw = strings.Trim(raw, `"`)
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// findingChangedDetails is the body detail of a 409 FINDING_CHANGED: the
// stored finding's version, status and update time, so the client knows it
// must re-read. The full finding is read again through GET (scope-checked).
type findingChangedDetails struct {
	FindingID  string     `json:"finding_id"`
	RowVersion *int64     `json:"row_version,omitempty"`
	Status     string     `json:"status,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

// writeFindingConflict answers a refused finding write. It reports whether
// err was one.
func writeFindingConflict(w http.ResponseWriter, err error) bool {
	var conflict *vulnerability.FindingConflictError
	if !errors.As(err, &conflict) {
		if !errors.Is(err, vulnerability.ErrFindingConflict) {
			return false
		}
		conflict = &vulnerability.FindingConflictError{}
	}
	details := findingChangedDetails{}
	if !conflict.FindingID.IsZero() {
		details.FindingID = conflict.FindingID.String()
	}
	if cur := conflict.Current; cur != nil {
		v := cur.RowVersion()
		at := cur.UpdatedAt()
		details.RowVersion = &v
		details.Status = cur.Status().String()
		details.UpdatedAt = &at
	}
	e := apierror.New(http.StatusConflict, CodeFindingChanged,
		"The finding was changed by someone else. Reload it and try again.")
	e.Details = details
	e.WriteJSON(w)
	return true
}
