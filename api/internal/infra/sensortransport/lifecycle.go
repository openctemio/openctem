package sensortransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// EnableMTLS prepares the gRPC binding (Start starts it).
func (s *Server) EnableMTLS(cfg MTLSConfig, ca *CA, keys KeyResolver) error {
	srv, err := s.NewMTLSServer(cfg, ca, keys)
	if err != nil {
		return err
	}
	if len(cfg.TrustedProxies) > 0 {
		if _, err := proxyproto.PolicyFromRanges(cfg.TrustedProxies, proxyproto.USE, proxyproto.REJECT); err != nil {
			return fmt.Errorf("SENSOR_MTLS_TRUSTED_PROXIES: %w", err)
		}
	}
	s.mtls, s.mtlsProxies = srv, cfg.TrustedProxies
	return nil
}

// WakeBus delivers control-stream wakes across replicas (Redis, T12).
type WakeBus interface {
	Start(ctx context.Context) error
}

// SetWakeBus wires the cross-replica wake bus Start starts.
func (s *Server) SetWakeBus(b WakeBus) { s.wakeBus = b }

// Start starts the cross-replica wake bus (when set) and the gRPC binding
// (when EnableMTLS prepared it). Without the bus each replica wakes only its
// own streams and the others see changes at their periodic re-check.
func (s *Server) Start(ctx context.Context) error {
	if s.wakeBus != nil {
		if err := s.wakeBus.Start(ctx); err != nil {
			s.log.Error("sensor wake bus not started: streams on other replicas wake at their re-check", "error", err)
		}
	}
	if s.mtls == nil {
		return nil
	}
	ln, err := net.Listen("tcp", s.mtls.Addr)
	if err != nil {
		if s.adv != nil {
			s.adv.set(GRPCStatus{State: GRPCUnavailable, Reason: ReasonListenerFailed, CheckedAt: time.Now()})
		}
		return err
	}
	if len(s.mtlsProxies) > 0 {
		policy, err := proxyproto.PolicyFromRanges(s.mtlsProxies, proxyproto.USE, proxyproto.REJECT)
		if err != nil {
			_ = ln.Close()
			return err
		}
		ln = &proxyproto.Listener{Listener: ln, ConnPolicy: policy, ReadHeaderTimeout: 5 * time.Second}
	}
	s.log.Info("sensor protocol v3 gRPC binding listening", "addr", ln.Addr().String())
	go func() {
		if err := s.mtls.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("sensor protocol v3 gRPC binding stopped", "error", err)
		}
	}()
	if s.prober != nil {
		go s.prober.Run(ctx)
	}
	return nil
}

// SetProber sets the self-probe Start runs once the gRPC binding listens;
// it decides whether Hello advertises the endpoint.
func (s *Server) SetProber(p *Prober) { s.prober = p }

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

// SetGRPCEndpoint sets a fixed host:port Hello names for the gRPC binding
// ("" when it is not served). Call it before serving.
func (s *Server) SetGRPCEndpoint(endpoint string) { s.cfg.GRPCEndpoint = endpoint }

// SetAdvertiser makes Hello name the endpoint a holds while its self-probe
// passes (and none otherwise). Call it before serving.
func (s *Server) SetAdvertiser(a *Advertiser) { s.adv = a }

// GRPCStatus is the gRPC binding's state (fixed endpoint: advertised).
func (s *Server) GRPCStatus() GRPCStatus {
	if s.adv != nil {
		return s.adv.Status()
	}
	if s.cfg.GRPCEndpoint != "" {
		return GRPCStatus{State: GRPCAdvertised, Endpoint: s.cfg.GRPCEndpoint}
	}
	return GRPCStatus{State: GRPCUnavailable, Reason: ReasonNoPublicHost}
}

// grpcEndpoint is the endpoint Hello names now.
func (s *Server) grpcEndpoint() string {
	if s.adv != nil {
		return s.adv.Endpoint()
	}
	return s.cfg.GRPCEndpoint
}
