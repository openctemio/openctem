package http

// The platform administration console on its own listener (RFC-022
// revision 20, the admin plane). With ADMIN_LISTEN_ADDR set, the API serves
// /api/v1/admin only there, and the public listener answers 404 for it; the
// admin listener answers 404 for every tenant, sensor or public route. Both
// share the one router and its global middleware (the console network gate
// included), so the console's own guards are unchanged: what changes is
// where it can be reached. The gateway and the web console route the admin
// origin to this listener, and an installation can keep it off the network
// entirely.

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
)

// adminListenerPaths are what the admin listener serves besides the console
// API: the health probe its container check uses.
var adminListenerPaths = map[string]bool{"/health": true}

// publicOnly answers 404 for the console API, so it does not exist on the
// public listener.
func publicOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if middleware.IsAdminAPIPath(r.URL.Path) {
			apierror.NotFound("resource").WriteJSON(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminOnly answers 404 for everything but the console API and the health
// probe, so no tenant, sensor or public route is reachable through the admin
// listener (and a mis-gated one could not be reached through it either).
func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !middleware.IsAdminAPIPath(r.URL.Path) && !adminListenerPaths[r.URL.Path] {
			apierror.NotFound("resource").WriteJSON(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminListenerEnabled reports whether the console has its own listener.
func (s *Server) adminListenerEnabled() bool {
	return s.config.AdminPlane.ListenAddr != ""
}

// newAdminServer builds the admin listener's server over the router. Plain
// HTTP: it is an internal listener behind the gateway or the web console,
// never published as is.
func (s *Server) newAdminServer() *http.Server {
	return &http.Server{
		Addr:              s.config.AdminPlane.ListenAddr,
		Handler:           adminOnly(s.router.Handler()),
		ReadTimeout:       s.config.Server.ReadTimeout,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      s.config.Server.WriteTimeout,
		IdleTimeout:       time.Minute,
	}
}

// startAdminListener serves the admin listener until it is shut down.
func (s *Server) startAdminListener() error {
	s.logger.Info("starting the platform admin console listener", "addr", s.adminServer.Addr)
	if err := s.adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("admin console listener: %w", err)
	}
	return nil
}
