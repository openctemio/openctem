package httpsec

import (
	"net"
	"net/http"
	"sync"
	"weak"
)

// Guarded transports keep idle keep-alive connections. A connection is vetted
// when it is dialed, so after the console closes a private range an idle
// connection into that range could still be reused. Every transport built by
// this package is registered here (weakly, so a dropped client is still
// collected), and narrowing the policy closes their idle connections.
// Requests in flight finish; the next request dials again through the guard.
// A transport built elsewhere around SafeDialContext is not registered: it
// reuses its idle connections until they time out.

var (
	guardedTransportsMu sync.Mutex
	guardedTransports   []weak.Pointer[http.Transport]
)

// registerGuardedTransport records tr so a narrowing policy closes its idle
// connections. Collected entries are pruned on the way.
func registerGuardedTransport(tr *http.Transport) {
	guardedTransportsMu.Lock()
	defer guardedTransportsMu.Unlock()
	live := guardedTransports[:0]
	for _, w := range guardedTransports {
		if w.Value() != nil {
			live = append(live, w)
		}
	}
	live = append(live, weak.Make(tr))
	guardedTransports = live
}

// closeGuardedIdleConnections closes the idle connections of every registered
// transport that is still alive.
func closeGuardedIdleConnections() {
	guardedTransportsMu.Lock()
	trs := make([]*http.Transport, 0, len(guardedTransports))
	for _, w := range guardedTransports {
		if tr := w.Value(); tr != nil {
			trs = append(trs, tr)
		}
	}
	guardedTransportsMu.Unlock()
	for _, tr := range trs {
		tr.CloseIdleConnections()
	}
}

// narrows reports whether some range of prev is not wholly inside a range of
// next, so an address reachable before is refused now.
func narrows(prev, next []*net.IPNet) bool {
	for _, p := range prev {
		if !coveredBy(p, next) {
			return true
		}
	}
	return false
}

func coveredBy(n *net.IPNet, nets []*net.IPNet) bool {
	pOnes, pBits := n.Mask.Size()
	for _, o := range nets {
		oOnes, oBits := o.Mask.Size()
		if pBits == oBits && oOnes <= pOnes && o.Contains(n.IP) {
			return true
		}
	}
	return false
}
