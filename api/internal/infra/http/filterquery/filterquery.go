// Package filterquery is the HTTP side of the list query contract
// (docs/rfcs/RFC-048-list-query-contract.md): it decodes a request's filter
// with pkg/filterspec, answers a bad filter with 400 INVALID_FILTER, and
// runs the rollout for unknown and renamed params:
//
//   - an alias (an old param name) works, and the response carries
//     Deprecation (RFC 9745), Sunset (RFC 8594) and a Warning naming the new
//     param; deprecated_query_param_requests_total counts it;
//   - an unknown param, in warn mode, is ignored as before, logged by NAME
//     only (never its value), counted in filter_unknown_param_total, and
//     answered with Deprecation and a Warning; in strict mode it is a 400.
//
// Values are never logged and never become metric labels.
package filterquery

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

var (
	// UnknownParamRequests counts ignored unknown params (warn mode).
	UnknownParamRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "filter_unknown_param_total",
		Help: "Query params a migrated list endpoint ignored because its field registry does not know them (RFC-048 warn mode)",
	}, []string{"route", "param"})

	// DeprecatedParamRequests counts uses of old param names.
	DeprecatedParamRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "deprecated_query_param_requests_total",
		Help: "Requests that used a deprecated query param name (RFC-048 aliases), by route, param and kind of caller",
	}, []string{"route", "param", "client"})
)

// maxUnknownLabels bounds the distinct unknown-param label values per
// process; later names are counted as "other".
const maxUnknownLabels = 64

var (
	unknownMu     sync.Mutex
	unknownLabels = map[string]bool{}
)

func unknownLabel(name string) string {
	name = filterspec.SafeName(name)
	unknownMu.Lock()
	defer unknownMu.Unlock()
	if unknownLabels[name] {
		return name
	}
	if len(unknownLabels) >= maxUnknownLabels {
		return "other"
	}
	unknownLabels[name] = true
	return name
}

// Route is one migrated endpoint.
type Route struct {
	// Name is a fixed metric label ("GET /findings"). Never derive it from
	// the request path.
	Name     string
	Registry *filterspec.Registry
	Options  filterspec.Options
	// DeprecatedAt and SunsetAt date the aliases and the warn window.
	DeprecatedAt time.Time
	SunsetAt     time.Time
	Logger       *logger.Logger
}

// ParseQuery decodes the GET params. On a bad filter it writes the 400 and
// returns ok=false.
func (rt Route) ParseQuery(w http.ResponseWriter, r *http.Request) (*filterspec.Spec, bool) {
	spec, err := filterspec.ParseValues(r.URL.Query(), rt.Registry, rt.Options)
	if err != nil {
		WriteError(w, err)
		return nil, false
	}
	rt.announce(w, r, spec)
	return spec, true
}

// ParseBody decodes a FilterDocument body, reading at most
// filterspec.MaxBodyBytes before decoding.
func (rt Route) ParseBody(w http.ResponseWriter, r *http.Request) (*filterspec.Spec, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, filterspec.MaxBodyBytes+1))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			WriteError(w, &filterspec.Error{Details: []filterspec.Detail{{Path: "$", Reason: "document is larger than 32 KB"}}})
			return nil, false
		}
		apierror.BadRequest("Could not read the request body").WriteJSON(w)
		return nil, false
	}
	spec, err := filterspec.ParseDocument(body, rt.Registry, rt.Options)
	if err != nil {
		WriteError(w, err)
		return nil, false
	}
	return spec, true
}

// WriteError writes a filterspec error as 400 INVALID_FILTER; any other
// error is a 500 (Compile only fails on a programming error otherwise).
func WriteError(w http.ResponseWriter, err error) {
	if fe, ok := filterspec.AsError(err); ok {
		fe.APIError().WriteJSON(w)
		return
	}
	apierror.InternalError(err).WriteJSON(w)
}

// announce sets the deprecation headers and counts aliases and unknown
// params.
func (rt Route) announce(w http.ResponseWriter, r *http.Request, spec *filterspec.Spec) {
	if len(spec.AliasesUsed) == 0 && len(spec.UnknownParams) == 0 {
		return
	}
	h := w.Header()
	if !rt.DeprecatedAt.IsZero() {
		h.Set("Deprecation", "@"+strconv.FormatInt(rt.DeprecatedAt.Unix(), 10))
	}
	client := middleware.DeprecatedRouteClient(r)
	for _, a := range spec.AliasesUsed {
		DeprecatedParamRequests.WithLabelValues(rt.Name, a.Old, client).Inc()
		h.Add("Warning", `299 - "query parameter `+a.Old+` is deprecated; use `+a.New+`"`)
	}
	if len(spec.AliasesUsed) > 0 && !rt.SunsetAt.IsZero() {
		h.Set("Sunset", rt.SunsetAt.UTC().Format(http.TimeFormat))
	}
	if len(spec.UnknownParams) > 0 {
		names := make([]string, 0, len(spec.UnknownParams))
		for _, p := range spec.UnknownParams {
			label := unknownLabel(p)
			UnknownParamRequests.WithLabelValues(rt.Name, label).Inc()
			names = append(names, filterspec.SafeName(p))
		}
		h.Add("Warning", `299 - "unknown query parameters ignored: `+strings.Join(names, ", ")+`; they will be rejected"`)
		if rt.Logger != nil {
			rt.Logger.Info("list filter: unknown query params ignored",
				"route", rt.Name, "params", strings.Join(names, ","), "client", client)
		}
	}
}
