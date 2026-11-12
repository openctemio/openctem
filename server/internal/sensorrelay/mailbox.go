package sensorrelay

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/sensorproto/relay"
)

// errFull: a quota would be exceeded; the caller answers 429.
var errFull = errors.New("sensorrelay: mailbox full")

type entry struct {
	sensor string
	env    []byte
	at     time.Time
}

// box is one queue with a wake-up channel that is closed and replaced on
// every put.
type box struct {
	items []entry
	bytes int64
	wake  chan struct{}
}

func newBox() *box { return &box{wake: make(chan struct{})} }

func (b *box) signal() {
	close(b.wake)
	b.wake = make(chan struct{})
}

type sensorKey struct{ realm, sensor string }

type usage struct {
	items int
	bytes int64
}

// mailboxes holds every envelope in memory, bounded per sensor and in
// total. Nothing is written to disk.
type mailboxes struct {
	lim Limits
	now func() time.Time

	mu    sync.Mutex
	up    map[string]*box // realm -> envelopes from its sensors
	upUse map[sensorKey]usage
	down  map[sensorKey]*box // envelopes for one sensor
	total int64
	// realmBytes is what each realm holds (both directions), so one realm
	// cannot fill the relay for the others.
	realmBytes map[string]int64
}

func newMailboxes(lim Limits, now func() time.Time) *mailboxes {
	return &mailboxes{lim: lim, now: now, up: map[string]*box{}, upUse: map[sensorKey]usage{}, down: map[sensorKey]*box{}, realmBytes: map[string]int64{}}
}

// roomUp reports whether an envelope of n bytes from the sensor would fit
// now. It lets the server refuse before it reads the body; putUp stays the
// authority (another request may take the room in between).
func (m *mailboxes) roomUp(realm, sensor string, n int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.upUse[sensorKey{realm, sensor}]
	return u.items+1 <= m.lim.MailboxItems && u.bytes+n <= m.lim.MailboxBytes &&
		m.total+n <= m.lim.TotalBytes && m.realmBytes[realm]+n <= m.lim.RealmBytes
}

// roomDown is roomUp for an envelope queued for a sensor.
func (m *mailboxes) roomDown(realm, sensor string, n int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items int
	var held int64
	if b := m.down[sensorKey{realm, sensor}]; b != nil {
		items, held = len(b.items), b.bytes
	}
	return items+1 <= m.lim.MailboxItems && held+n <= m.lim.MailboxBytes &&
		m.total+n <= m.lim.TotalBytes && m.realmBytes[realm]+n <= m.lim.RealmBytes
}

// release gives back bytes a realm no longer holds; the caller holds m.mu.
func (m *mailboxes) release(realm string, n int64) {
	if m.realmBytes[realm] -= n; m.realmBytes[realm] <= 0 {
		delete(m.realmBytes, realm)
	}
}

// putUp queues a sensor's envelope for its realm's connector.
func (m *mailboxes) putUp(realm, sensor string, env []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := sensorKey{realm, sensor}
	u := m.upUse[k]
	n := int64(len(env))
	if u.items+1 > m.lim.MailboxItems || u.bytes+n > m.lim.MailboxBytes || m.total+n > m.lim.TotalBytes ||
		m.realmBytes[realm]+n > m.lim.RealmBytes {
		return errFull
	}
	b := m.up[realm]
	if b == nil {
		b = newBox()
		m.up[realm] = b
	}
	b.items = append(b.items, entry{sensor: sensor, env: env, at: m.now()})
	b.bytes += n
	m.upUse[k] = usage{items: u.items + 1, bytes: u.bytes + n}
	m.total += n
	m.realmBytes[realm] += n
	b.signal()
	return nil
}

// putDown queues an envelope for one sensor.
func (m *mailboxes) putDown(realm, sensor string, env []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := sensorKey{realm, sensor}
	b := m.down[k]
	if b == nil {
		b = newBox()
		m.down[k] = b
	}
	n := int64(len(env))
	if len(b.items)+1 > m.lim.MailboxItems || b.bytes+n > m.lim.MailboxBytes || m.total+n > m.lim.TotalBytes ||
		m.realmBytes[realm]+n > m.lim.RealmBytes {
		return errFull
	}
	b.items = append(b.items, entry{env: env, at: m.now()})
	b.bytes += n
	m.total += n
	m.realmBytes[realm] += n
	b.signal()
	return nil
}

// take removes up to maxItems / maxBytes envelopes from the box returned by
// get, waiting until some arrive or ctx ends. withSensor keeps the sensor
// id on each item (connector batches).
func (m *mailboxes) take(ctx context.Context, realm string, get func() *box, onTake func(entry), maxItems int, maxBytes int64, withSensor bool) []relay.Item {
	for {
		m.mu.Lock()
		b := get()
		if len(b.items) > 0 {
			var out []relay.Item
			var size int64
			i := 0
			for ; i < len(b.items) && len(out) < maxItems; i++ {
				e := b.items[i]
				if len(out) > 0 && size+int64(len(e.env)) > maxBytes {
					break
				}
				size += int64(len(e.env))
				it := relay.Item{Envelope: e.env}
				if withSensor {
					it.Sensor = e.sensor
				}
				out = append(out, it)
				if onTake != nil {
					onTake(e)
				}
			}
			b.items = append([]entry(nil), b.items[i:]...)
			b.bytes -= size
			m.total -= size
			m.release(realm, size)
			m.mu.Unlock()
			return out
		}
		wake := b.wake
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		}
	}
}

// takeUp is the connector's long-poll on its realm.
func (m *mailboxes) takeUp(ctx context.Context, realm string, maxItems int, maxBytes int64) []relay.Item {
	get := func() *box {
		b := m.up[realm]
		if b == nil {
			b = newBox()
			m.up[realm] = b
		}
		return b
	}
	onTake := func(e entry) {
		k := sensorKey{realm, e.sensor}
		u := m.upUse[k]
		u.items--
		u.bytes -= int64(len(e.env))
		if u.items <= 0 {
			delete(m.upUse, k)
		} else {
			m.upUse[k] = u
		}
	}
	return m.take(ctx, realm, get, onTake, maxItems, maxBytes, true)
}

// takeDown is a sensor's long-poll on its own mailbox.
func (m *mailboxes) takeDown(ctx context.Context, realm, sensor string, maxItems int, maxBytes int64) []relay.Item {
	k := sensorKey{realm, sensor}
	get := func() *box {
		b := m.down[k]
		if b == nil {
			b = newBox()
			m.down[k] = b
		}
		return b
	}
	return m.take(ctx, realm, get, nil, maxItems, maxBytes, false)
}

// expire drops envelopes older than the TTL and empty idle boxes; it
// returns how many envelopes went.
func (m *mailboxes) expire() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := m.now().Add(-m.lim.TTL)
	dropped := 0
	for realm, b := range m.up {
		keep := b.items[:0]
		for _, e := range b.items {
			if e.at.Before(cutoff) {
				n := int64(len(e.env))
				b.bytes -= n
				m.total -= n
				m.release(realm, n)
				k := sensorKey{realm, e.sensor}
				u := m.upUse[k]
				u.items--
				u.bytes -= n
				if u.items <= 0 {
					delete(m.upUse, k)
				} else {
					m.upUse[k] = u
				}
				dropped++
				continue
			}
			keep = append(keep, e)
		}
		b.items = keep
	}
	for k, b := range m.down {
		keep := b.items[:0]
		for _, e := range b.items {
			if e.at.Before(cutoff) {
				n := int64(len(e.env))
				b.bytes -= n
				m.total -= n
				m.release(k.realm, n)
				dropped++
				continue
			}
			keep = append(keep, e)
		}
		b.items = keep
		if len(b.items) == 0 {
			// Close the wake channel so a waiting poll re-reads the map and
			// finds a fresh box; then forget the idle one.
			b.signal()
			delete(m.down, k)
		}
	}
	return dropped
}

// held returns the bytes held.
func (m *mailboxes) held() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.total
}
