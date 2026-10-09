package sensor

import (
	"sync"
	"time"
)

// keyUseInterval is how often one sensor's key use from one address is
// written (last seen, last IP, key last used). Every request used to write
// it, from a goroutine of its own: a sensor flooding requests turned each
// into two database writes before any rate limit applied.
const keyUseInterval = 15 * time.Second

// maxKeyUseEntries bounds the debouncer's memory; past it, entries older
// than keyUseInterval are dropped, and if none are, everything is.
const maxKeyUseEntries = 50_000

// keyUseDebouncer remembers when each (sensor, address) last recorded a key
// use. The zero value is ready to use.
type keyUseDebouncer struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// due reports whether the key use under key should be written at now, and
// if so remembers now. A new address is always due (the IP-change event
// depends on it).
func (d *keyUseDebouncer) due(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == nil {
		d.last = make(map[string]time.Time)
	}
	if t, ok := d.last[key]; ok && now.Sub(t) >= 0 && now.Sub(t) < keyUseInterval {
		return false
	}
	if len(d.last) >= maxKeyUseEntries {
		for k, t := range d.last {
			if now.Sub(t) >= keyUseInterval {
				delete(d.last, k)
			}
		}
		if len(d.last) >= maxKeyUseEntries {
			clear(d.last)
		}
	}
	d.last[key] = now
	return true
}
