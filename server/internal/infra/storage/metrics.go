package storage

// Storage metrics (api/docs/architecture/file-storage.md, "Metrics"). Labels
// have a fixed, small cardinality: no tenant or file in any label.

import (
	"context"
	"io"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
)

var (
	storageOps = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "openctem_storage_operations_total",
		Help: "File storage operations by operation (upload, download, delete, erase, presign), backend (server, organization) and result (ok, error).",
	}, []string{"op", "backend", "result"})
	storageOpSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "openctem_storage_operation_seconds",
		Help:    "Duration of file storage operations (uploads include the transfer).",
		Buckets: []float64{0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
	}, []string{"op", "backend"})
	storageBytesWritten = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "openctem_storage_bytes_written_total",
		Help: "Bytes written to the file storage, by backend.",
	}, []string{"backend"})
	storageEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "openctem_storage_events_total",
		Help: "Storage policy outcomes: quota_rejected, purged_parent_deleted, purged_never_linked, scan_clean, scan_infected, scan_error.",
	}, []string{"event"})
)

// Backend labels.
const (
	BackendServer       = "server"
	BackendOrganization = "organization"
)

// Instrument wraps a FileStorage so its operations are counted and timed.
// A wrapped storage still signs direct downloads when the inner one can.
func Instrument(fs attachment.FileStorage, backend string) attachment.FileStorage {
	if fs == nil {
		return nil
	}
	return &instrumented{inner: fs, backend: backend}
}

type instrumented struct {
	inner   attachment.FileStorage
	backend string
}

func (m *instrumented) observe(op string, start time.Time, err error) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	storageOps.WithLabelValues(op, m.backend, result).Inc()
	storageOpSeconds.WithLabelValues(op, m.backend).Observe(time.Since(start).Seconds())
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (m *instrumented) Upload(ctx context.Context, tenantID, filename, contentType string, r io.Reader) (string, error) {
	start := time.Now()
	cr := &countingReader{r: r}
	key, err := m.inner.Upload(ctx, tenantID, filename, contentType, cr)
	m.observe("upload", start, err)
	if err == nil {
		storageBytesWritten.WithLabelValues(m.backend).Add(float64(cr.n))
	}
	return key, err
}

func (m *instrumented) Download(ctx context.Context, tenantID, key string) (io.ReadCloser, string, error) {
	start := time.Now()
	rc, ct, err := m.inner.Download(ctx, tenantID, key)
	m.observe("download", start, err)
	return rc, ct, err
}

func (m *instrumented) Delete(ctx context.Context, tenantID, key string) error {
	start := time.Now()
	err := m.inner.Delete(ctx, tenantID, key)
	m.observe("delete", start, err)
	return err
}

func (m *instrumented) EraseTenant(ctx context.Context, tenantID string) (int, error) {
	start := time.Now()
	n, err := m.inner.EraseTenant(ctx, tenantID)
	m.observe("erase", start, err)
	return n, err
}

// PresignDownload signs through the inner storage, or answers
// ErrDirectDownloadUnavailable when it cannot sign.
func (m *instrumented) PresignDownload(ctx context.Context, tenantID, key, filename, contentType string, ttl time.Duration) (string, error) {
	dd, ok := m.inner.(attachment.DirectDownloader)
	if !ok {
		return "", attachment.ErrDirectDownloadUnavailable
	}
	start := time.Now()
	u, err := dd.PresignDownload(ctx, tenantID, key, filename, contentType, ttl)
	m.observe("presign", start, err)
	return u, err
}

// Metrics records storage policy outcomes for the attachment service.
type Metrics struct{}

// StorageEvent counts one policy outcome (see openctem_storage_events_total).
func (Metrics) StorageEvent(event string) { storageEvents.WithLabelValues(event).Inc() }
