package systemstatus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// WatchName is the controller's name.
const WatchName = "system-watch"

// RenotifyAfter is how long a standing warning waits before it is mailed
// again; a worse level is mailed at once.
const RenotifyAfter = 24 * time.Hour

// Notifier tells the active platform administrators (best effort, never
// blocks the watcher on slow mail).
type Notifier interface {
	NotifyAdmins(ctx context.Context, subject, htmlBody string) error
}

var (
	metricsOnce    sync.Once
	storageFree    = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "openctem_system_storage_free_ratio", Help: "Free fraction of a configured data volume."}, []string{"volume"})
	storageLevelG  = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "openctem_system_storage_level", Help: "0 ok, 1 warning, 2 critical."}, []string{"volume"})
	backupAge      = prometheus.NewGauge(prometheus.GaugeOpts{Name: "openctem_system_backup_age_seconds", Help: "Age of the last successful backup; absent until one is reported."})
	backupLevelG   = prometheus.NewGauge(prometheus.GaugeOpts{Name: "openctem_system_backup_level", Help: "0 ok, 1 warning."})
	certExpiry     = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "openctem_system_certificate_expiry_seconds", Help: "Seconds until a certificate expires."}, []string{"name"})
	certLevelG     = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "openctem_system_certificate_level", Help: "0 ok, 1 warning, 2 critical."}, []string{"name"})
	databaseBytesG = prometheus.NewGauge(prometheus.GaugeOpts{Name: "openctem_system_database_bytes", Help: "Size of the connected database."})
)

func registerMetrics() {
	metricsOnce.Do(func() {
		prometheus.MustRegister(storageFree, storageLevelG, backupAge, backupLevelG, certExpiry, certLevelG, databaseBytesG)
	})
}

// check is one evaluated item.
type check struct {
	key, subject string
	level        int
	detail       string
}

type sent struct {
	level int
	at    time.Time
}

// Watcher evaluates the snapshot on an interval, sets the metrics and mails
// the administrators when a check gets worse. It implements the controller
// interface (Name, Interval, Reconcile).
type Watcher struct {
	c        *Collector
	n        Notifier
	log      *logger.Logger
	interval time.Duration
	now      func() time.Time

	mu   sync.Mutex
	last map[string]sent
}

// NewWatcher creates the watcher. n may be nil (metrics and log only).
func NewWatcher(c *Collector, n Notifier, interval time.Duration, log *logger.Logger) *Watcher {
	registerMetrics()
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &Watcher{c: c, n: n, log: log.With("controller", WatchName), interval: interval, now: time.Now, last: map[string]sent{}}
}

// Name implements controller.Controller.
func (w *Watcher) Name() string { return WatchName }

// Exclusive makes the controller manager run the watcher on one replica only,
// so administrators are not mailed once per replica.
func (w *Watcher) Exclusive() bool { return true }

// Interval implements controller.Controller.
func (w *Watcher) Interval() time.Duration { return w.interval }

// Reconcile implements controller.Controller. It returns the number of
// checks above ok.
func (w *Watcher) Reconcile(ctx context.Context) (int, error) {
	snap := w.c.Collect(ctx)
	checks := w.publish(snap)
	n := 0
	for _, ck := range checks {
		if ck.level > LevelOK {
			n++
		}
		w.handle(ctx, ck)
	}
	return n, nil
}

// publish sets the gauges and lists the checks.
func (w *Watcher) publish(s Snapshot) []check {
	out := make([]check, 0, len(s.Storage.Volumes)+len(s.Certificates)+1)
	for _, v := range s.Storage.Volumes {
		if !v.OK {
			continue
		}
		storageFree.WithLabelValues(v.Name).Set(v.FreeRatio)
		storageLevelG.WithLabelValues(v.Name).Set(float64(v.Level))
		out = append(out, check{key: "storage:" + v.Name, subject: "Free space on " + v.Name, level: v.Level,
			detail: fmt.Sprintf("%.0f%% free (%s of %s)", v.FreeRatio*100, humanBytes(v.FreeB), humanBytes(v.TotalB))})
	}
	if s.Storage.DatabaseOK {
		databaseBytesG.Set(float64(s.Storage.DatabaseB))
	}
	if s.Backup.Reported {
		backupAge.Set(float64(s.Backup.AgeSeconds))
		out = append(out, check{key: "backup", subject: "Database backup", level: s.Backup.Level,
			detail: fmt.Sprintf("last success %d hours ago", s.Backup.AgeSeconds/3600)})
	}
	backupLevelG.Set(float64(s.Backup.Level))
	for _, ce := range s.Certificates {
		if !ce.OK {
			continue
		}
		certExpiry.WithLabelValues(ce.Name).Set(float64(ce.ExpiresInSecs))
		certLevelG.WithLabelValues(ce.Name).Set(float64(ce.Level))
		out = append(out, check{key: "cert:" + ce.Name, subject: "Certificate " + ce.Name, level: ce.Level,
			detail: fmt.Sprintf("expires in %d days", ce.ExpiresInSecs/86400)})
	}
	return out
}

func (w *Watcher) handle(ctx context.Context, ck check) {
	now := w.now()
	w.mu.Lock()
	prev, had := w.last[ck.key]
	if ck.level == LevelOK {
		delete(w.last, ck.key)
		w.mu.Unlock()
		return
	}
	due := !had || ck.level > prev.level || now.Sub(prev.at) >= RenotifyAfter
	if due {
		w.last[ck.key] = sent{level: ck.level, at: now}
	}
	w.mu.Unlock()
	if !due {
		return
	}
	word := map[int]string{LevelWarning: "warning", LevelCritical: "critical"}[ck.level]
	w.log.Warn("system check degraded", "alert", "system_"+strings.SplitN(ck.key, ":", 2)[0], "check", ck.key, "level", word, "detail", ck.detail)
	if w.n == nil {
		return
	}
	subject := fmt.Sprintf("[%s] %s: %s", strings.ToUpper(word), ck.subject, ck.detail)
	body := fmt.Sprintf("<p>%s is at <strong>%s</strong>: %s.</p><p>Open the Health page in the platform console for the full picture.</p>",
		htmlEscape(ck.subject), word, htmlEscape(ck.detail))
	if err := w.n.NotifyAdmins(ctx, subject, body); err != nil {
		w.log.Warn("system check mail failed", "check", ck.key)
	}
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func humanBytes(b uint64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
