package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// csrfReasonCrossSite is the csrf_rejections_total label for a write a
// browser sent on behalf of another site.
const csrfReasonCrossSite = "cross_site"

// Sec-Fetch-Site values a browser sends for a request this site made itself
// (same-origin) or the user started (none).
const (
	fetchSiteSameOrigin = "same-origin"
	fetchSiteNone       = "none"
)

// RejectCrossSiteBrowser refuses a state-changing request that a browser sent
// on behalf of another site. It guards the routes that run before a session
// exists and set session cookies (sign-in, registration, password reset, the
// second factor, SSO and OAuth callbacks, the console's sign-in steps), which
// carry no double-submit token: without it a page on another site could post
// the attacker's credentials and sign the visitor into the attacker's account
// (login CSRF) when the API is reachable from browsers directly.
//
// A request is refused (403) when the browser says it is cross-site:
//   - Origin is present and names neither the host the request was sent to
//     (Host, or X-Forwarded-Host from the gateway) nor one of allowedOrigins
//     (CORS_ALLOWED_ORIGINS, the origins allowed to call the API from a
//     browser); "null" is refused, or
//   - there is no Origin and Sec-Fetch-Site is neither "same-origin" nor
//     "none".
//
// A request with neither header is let through: every browser sends Origin
// on a cross-origin POST, and the web console calls these routes from its
// server, which sends neither (it checks CSRF itself, web/src/lib/
// server-auth-cookies.ts). Safe methods are never checked.
func RejectCrossSiteBrowser(allowedOrigins []string, log *logger.Logger) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if origin := normalizeOrigin(o); origin != "" {
			allowed[origin] = struct{}{}
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) || !isCrossSiteBrowserRequest(r, allowed) {
				next.ServeHTTP(w, r)
				return
			}
			metrics.CSRFRejectionsTotal.WithLabelValues(csrfReasonCrossSite, r.Method).Inc()
			if log != nil {
				log.Debug("cross-site request refused", "path", logSafe(RedactPath(r.URL.Path)))
			}
			apierror.Forbidden("Cross-origin request refused").WriteJSON(w)
		})
	}
}

func isCrossSiteBrowserRequest(r *http.Request, allowed map[string]struct{}) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		site := r.Header.Get("Sec-Fetch-Site")
		return site != "" && site != fetchSiteSameOrigin && site != fetchSiteNone
	}
	if origin == "null" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return true
	}
	if strings.EqualFold(u.Host, r.Host) {
		return false
	}
	if fwd := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); fwd != "" && strings.EqualFold(u.Host, fwd) {
		return false
	}
	_, ok := allowed[normalizeOrigin(origin)]
	return !ok
}

// normalizeOrigin reduces a URL to its lower-case scheme://host[:port], or ""
// when it has no scheme or host.
func normalizeOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}
