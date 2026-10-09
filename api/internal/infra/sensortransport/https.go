package sensortransport

import (
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
	"github.com/openctemio/openctem/api/pkg/sensorproto/v3/sensorv3connect"
)

// HTTPSHandler is the HTTPS binding (RFC-059 T5), mounted at PathPrefix on
// the API listener ahead of the router: the platform's global middleware
// (request timeout, buffered writers) would cut the control stream, so the
// binding carries its own guards. authenticate is the RFC 9421 authenticator
// (handler.SensorResultsV2Handler.AuthenticateV3); nothing reaches the
// service without it. Bodies are limited before authentication reads them.
func (s *Server) HTTPSHandler(authenticate func(http.Handler) http.Handler) http.Handler {
	path, h := s.Handler()
	mux := http.NewServeMux()
	mux.Handle(PathPrefix+path, http.StripPrefix(PathPrefix, h))
	bound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStream(r) {
			// The control stream outlives the server's read and write
			// timeouts; the keepalive and the maximum stream age bound it.
			// Lifted only once the caller is authenticated, so an
			// unauthenticated request keeps the listener's deadlines.
			rc := http.NewResponseController(w)
			_ = rc.SetReadDeadline(time.Time{})
			_ = rc.SetWriteDeadline(time.Time{})
		}
		mux.ServeHTTP(w, r.WithContext(WithBinding(r.Context(), sensorv3.Binding_BINDING_HTTPS)))
	})
	limit := s.cfg.MaxContentBytes + maxEnvelopeBytes
	return recoverer(s.log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > limit {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		release, ok := s.admitUnary(w, r)
		defer release()
		if !ok {
			return
		}
		authenticate(bound).ServeHTTP(w, r)
	}))
}

// isStream reports whether r is the control stream.
func isStream(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, sensorv3connect.SensorServiceSubscribeProcedure)
}

// recoverer turns a panic into a 500 and a log line (the router's recovery
// middleware is not on this path).
func recoverer(log *logger.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel compared as net/http does
					panic(rec)
				}
				log.Error("panic in sensor v3 handler", "error", rec, "stack", string(debug.Stack()))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
