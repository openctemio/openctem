package sensortransport

import (
	"context"
	"errors"
	"net"
	"net/http"
)

// EnableMTLS prepares the gRPC binding (ListenMTLS starts it).
func (s *Server) EnableMTLS(cfg MTLSConfig, ca *CA, keys KeyResolver) error {
	srv, err := s.NewMTLSServer(cfg, ca, keys)
	if err != nil {
		return err
	}
	s.mtls = srv
	return nil
}

// ListenMTLS starts the gRPC binding when EnableMTLS prepared it.
func (s *Server) ListenMTLS() error {
	if s.mtls == nil {
		return nil
	}
	ln, err := net.Listen("tcp", s.mtls.Addr)
	if err != nil {
		return err
	}
	s.log.Info("sensor protocol v3 gRPC binding listening", "addr", ln.Addr().String())
	go func() {
		if err := s.mtls.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("sensor protocol v3 gRPC binding stopped", "error", err)
		}
	}()
	return nil
}

// Shutdown ends every control stream (on both bindings; call it before the
// API listener's own shutdown, which would otherwise wait for them) and
// stops the gRPC binding. Sensors reconnect to another replica.
func (s *Server) Shutdown(ctx context.Context) error {
	s.doneOnce.Do(func() { close(s.done) })
	if s.mtls == nil {
		return nil
	}
	return s.mtls.Shutdown(ctx)
}

// SetGRPCEndpoint sets the host:port Hello names for the gRPC binding (""
// when it is not served). Call it before serving.
func (s *Server) SetGRPCEndpoint(endpoint string) { s.cfg.GRPCEndpoint = endpoint }
