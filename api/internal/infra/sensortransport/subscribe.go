package sensortransport

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/coalesce"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// wakeJitter spreads the re-evaluation of the streams a wake reaches, so
// one new command does not run every stream's doorbell query at once.
const wakeJitter = 250 * time.Millisecond

// WakeCoalesce is the shortest gap between two deliveries of the same wake
// (one tenant's streams, one sensor's streams, or every stream): wakes
// inside it fold into one delivered when it ends (research/84 RE-12). One
// command release wakes every stream of the tenant on every replica, each
// re-authenticating and re-reading the doorbell; without the bound a tenant
// releasing or refusing commands in a loop drives that work at its own pace.
// A folded wake is delayed, never lost; the periodic re-check is the
// backstop.
const WakeCoalesce = 500 * time.Millisecond

// Hub holds the control streams of this replica and wakes them.
type Hub struct {
	mu           sync.Mutex
	byTenant     map[string]map[*stream]struct{}
	perSensor    map[string]int
	maxPerSensor int
	// wakes coalesces deliveries per tenant, per sensor and for WakeAll.
	wakes *coalesce.Throttle
}

type stream struct {
	tenantID string
	sensorID string
	wake     chan struct{}
}

// NewHub builds a hub that allows maxPerSensor streams per sensor (0: 4).
func NewHub(maxPerSensor int) *Hub {
	if maxPerSensor <= 0 {
		maxPerSensor = 4
	}
	return &Hub{byTenant: map[string]map[*stream]struct{}{}, perSensor: map[string]int{}, maxPerSensor: maxPerSensor,
		wakes: coalesce.New(WakeCoalesce)}
}

var errTooManyStreams = errors.New("too many control streams for this sensor")

func (h *Hub) add(tenantID, sensorID string) (*stream, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.perSensor[sensorID] >= h.maxPerSensor {
		return nil, errTooManyStreams
	}
	st := &stream{tenantID: tenantID, sensorID: sensorID, wake: make(chan struct{}, 1)}
	if h.byTenant[tenantID] == nil {
		h.byTenant[tenantID] = map[*stream]struct{}{}
	}
	h.byTenant[tenantID][st] = struct{}{}
	h.perSensor[sensorID]++
	return st, nil
}

func (h *Hub) remove(st *stream) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m := h.byTenant[st.tenantID]; m != nil {
		delete(m, st)
		if len(m) == 0 {
			delete(h.byTenant, st.tenantID)
		}
	}
	if h.perSensor[st.sensorID]--; h.perSensor[st.sensorID] <= 0 {
		delete(h.perSensor, st.sensorID)
	}
}

// Wake tells the streams of tenantID (only sensorID's when it is not "")
// to re-evaluate the doorbell, at most once per WakeCoalesce for the same
// tenant (or sensor). It never blocks. A tenant with no stream on this
// replica costs nothing.
func (h *Hub) Wake(tenantID, sensorID string) {
	h.mu.Lock()
	_, has := h.byTenant[tenantID]
	h.mu.Unlock()
	if !has {
		return
	}
	key := "t:" + tenantID
	if sensorID != "" {
		key = "s:" + tenantID + "/" + sensorID
	}
	h.wakes.Do(key, func() { h.wakeNow(tenantID, sensorID) })
}

func (h *Hub) wakeNow(tenantID, sensorID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for st := range h.byTenant[tenantID] {
		if sensorID == "" || st.sensorID == sensorID {
			select {
			case st.wake <- struct{}{}:
			default:
			}
		}
	}
}

// WakeAll wakes every stream (a change whose tenant is not known, e.g. a
// bulk re-queue by the reaper), at most once per WakeCoalesce.
func (h *Hub) WakeAll() {
	h.wakes.Do("*", h.wakeAllNow)
}

func (h *Hub) wakeAllNow() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.byTenant {
		for st := range m {
			select {
			case st.wake <- struct{}{}:
			default:
			}
		}
	}
}

// Streams is the number of open control streams.
func (h *Hub) Streams() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.byTenant {
		n += len(m)
	}
	return n
}

// Subscribe is the control stream (RFC-059 §6): the doorbell now, again
// whenever a wake or the periodic re-check changes it, and a keepalive. The
// identity is re-resolved on every re-check and wake; a revoked key or
// sensor ends the stream with UNAUTHENTICATED.
func (s *Server) Subscribe(ctx context.Context, _ *connect.Request[sensorv3.SubscribeRequest], out *connect.ServerStream[sensorv3.SubscribeResponse]) error {
	_, hints, auth := s.backend()
	id, ok := handler.SensorIdentityFrom(ctx)
	if !ok || hints == nil || auth == nil {
		return connect.NewError(connect.CodeUnauthenticated, errNoIdentity)
	}
	// The open rate first: a refused open costs no database work.
	if !s.opens.allow(id.Sensor.ID.String()) {
		metrics.SensorStreamOpensRefusedTotal.WithLabelValues("rate").Inc()
		return connect.NewError(connect.CodeResourceExhausted, errStreamOpenRate)
	}
	st, err := s.hub.add(id.Sensor.TenantID.String(), id.Sensor.ID.String())
	if err != nil {
		metrics.SensorStreamOpensRefusedTotal.WithLabelValues("concurrent").Inc()
		return connect.NewError(connect.CodeResourceExhausted, err)
	}
	defer s.hub.remove(st)

	// A jittered maximum age: the sensor reconnects, the identity is
	// resolved from scratch and streams rebalance across replicas.
	age := s.cfg.MaxStreamAge - jitter(s.cfg.MaxStreamAge/5)
	deadline := time.NewTimer(age)
	defer deadline.Stop()
	keepalive := time.NewTicker(s.cfg.Keepalive)
	defer keepalive.Stop()
	recheck := time.NewTicker(s.cfg.Recheck)
	defer recheck.Stop()

	var last *sensorv3.SubscribeResponse
	send := func(force bool) error {
		ev := s.event(handler.WithSensorIdentity(ctx, id), hints, id.Sensor.ID.String())
		if !force && last != nil && sameEvent(last, ev) {
			return nil
		}
		last = ev
		keepalive.Reset(s.cfg.Keepalive)
		return out.Send(ev)
	}
	// refresh re-resolves the identity and sends the doorbell: always after
	// a wake (something changed), only when it differs after a re-check.
	refresh := func(force bool) error {
		fresh, err := auth.Reauthenticate(ctx, id)
		if err != nil {
			return connect.NewError(connect.CodeUnauthenticated, errors.New("sensor identity no longer valid"))
		}
		id = fresh
		return send(force)
	}

	if err := send(true); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.done:
			return nil
		case <-deadline.C:
			return nil
		case <-keepalive.C:
			if err := out.Send(&sensorv3.SubscribeResponse{Status: last.GetStatus(), Keepalive: true}); err != nil {
				return err
			}
		case <-recheck.C:
			if err := refresh(false); err != nil {
				return err
			}
		case <-st.wake:
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(jitter(wakeJitter)):
			}
			if err := refresh(true); err != nil {
				return err
			}
		}
	}
}

// event is the doorbell for the sensor in ctx as a stream event.
func (s *Server) event(ctx context.Context, hints Hints, sensorID string) *sensorv3.SubscribeResponse {
	h := hints.StreamHints(ctx, s.runningOf(sensorID))
	return &sensorv3.SubscribeResponse{
		Status:           h.Status,
		PendingJobs:      int32(min(h.PendingJobs, 1<<20)), //nolint:gosec // bounded
		Actions:          h.Actions,
		CancelCommandIds: h.CancelCommandIDs,
		ConfigVersion:    h.ConfigVersion,
	}
}

func sameEvent(a, b *sensorv3.SubscribeResponse) bool {
	return a.GetStatus() == b.GetStatus() && a.GetPendingJobs() == b.GetPendingJobs() &&
		a.GetConfigVersion() == b.GetConfigVersion() &&
		slices.Equal(a.GetActions(), b.GetActions()) && slices.Equal(a.GetCancelCommandIds(), b.GetCancelCommandIds())
}

// jitter is a random duration in [0, max).
func jitter(maxDur time.Duration) time.Duration {
	if maxDur <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxDur)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}
