// Package systemstatus is the platform console's Health page (RFC-114): a
// read-only, aggregate-only view of the installation's essentials (service
// health, free space, backup age, certificate expiry, version) and the watcher
// that tells the platform administrators when one gets worse.
//
// Nothing here takes a request-supplied path or URL: every probe target comes
// from the operator's environment. Nothing returned carries a path, a URL, a
// host name or an error text: a failing check reports a fixed code.
package systemstatus

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Levels of a check.
const (
	LevelOK       = 0
	LevelWarning  = 1
	LevelCritical = 2
)

// Thresholds (RFC-114 section 4.1).
const (
	StorageWarnFreeRatio     = 0.20
	StorageCriticalFreeRatio = 0.10
	BackupMaxAge             = 26 * time.Hour
	CertWarnWithin           = 30 * 24 * time.Hour
	CertCriticalWithin       = 7 * 24 * time.Hour

	maxFileBytes   = 64 << 10
	probeTimeout   = 3 * time.Second
	backupMetric   = "openctem_backup_last_success_timestamp_seconds"
	backupExitCode = "openctem_backup_last_exit_code"
)

// Fixed error codes (never raw error text).
const (
	CodeUnreachable = "unreachable"
	CodeUnhealthy   = "unhealthy"
	CodeUnreadable  = "unreadable"
)

// Service is one health probe's outcome.
type Service struct {
	Name       string  `json:"name"`
	Configured bool    `json:"configured"`
	OK         bool    `json:"ok"`
	LatencyMS  float64 `json:"latency_ms"`
	Code       string  `json:"code,omitempty"`
	// Detail is a count for aggregates (connected sensors), else 0.
	Detail int64 `json:"detail,omitempty"`
}

// Volume is one measured data path, shown by its configured name only.
type Volume struct {
	Name      string  `json:"name"`
	OK        bool    `json:"ok"`
	TotalB    uint64  `json:"total_bytes"`
	UsedB     uint64  `json:"used_bytes"`
	FreeB     uint64  `json:"free_bytes"`
	FreeRatio float64 `json:"free_ratio"`
	Level     int     `json:"level"`
}

// Storage is the volumes and the database size.
type Storage struct {
	Volumes    []Volume `json:"volumes"`
	DatabaseB  int64    `json:"database_bytes"`
	DatabaseOK bool     `json:"database_ok"`
}

// Backup is the last successful backup.
type Backup struct {
	// Reported is false when no status file is configured or it holds no
	// success time.
	Reported    bool       `json:"reported"`
	LastSuccess *time.Time `json:"last_success_at,omitempty"`
	AgeSeconds  int64      `json:"age_seconds,omitempty"`
	LastFailed  bool       `json:"last_failed,omitempty"`
	Level       int        `json:"level"`
}

// Certificate is one certificate's expiry.
type Certificate struct {
	Name          string    `json:"name"`
	OK            bool      `json:"ok"`
	NotAfter      time.Time `json:"not_after,omitempty"`
	ExpiresInSecs int64     `json:"expires_in_seconds,omitempty"`
	Level         int       `json:"level"`
}

// VersionCheck is the version-check result (RFC-105), reduced to what the
// page shows: no feed URL, no release notes.
type VersionCheck struct {
	Enabled       bool       `json:"enabled"`
	Configured    bool       `json:"configured"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	// AppliedAt is the last time a verified release feed was applied (the
	// last success); nil when none ever was.
	AppliedAt       *time.Time `json:"applied_at,omitempty"`
	Latest          string     `json:"latest,omitempty"`
	UpdateAvailable bool       `json:"update_available"`
	Advisories      int        `json:"advisories"`
	Severity        string     `json:"severity,omitempty"`
	Stale           bool       `json:"stale"`
}

// Version is the running build and the version-check result.
type Version struct {
	Running string        `json:"running"`
	Channel string        `json:"channel,omitempty"`
	Check   *VersionCheck `json:"check,omitempty"`
}

// Snapshot is GET /api/v1/admin/system.
type Snapshot struct {
	Services     []Service     `json:"services"`
	Storage      Storage       `json:"storage"`
	Backup       Backup        `json:"backup"`
	Certificates []Certificate `json:"certificates"`
	Version      Version       `json:"version"`
	// Level is the worst level of any check.
	Level     int       `json:"level"`
	CheckedAt time.Time `json:"checked_at"`
}

// NamedPath is an operator-chosen name for a path or URL.
type NamedPath struct{ Name, Value string }

// ParseNamed parses "name=value,name=value". Entries without a name or a
// value are dropped; names are cut to 40 characters.
func ParseNamed(s string) []NamedPath {
	parts := strings.Split(s, ",")
	out := make([]NamedPath, 0, len(parts))
	for _, part := range parts {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			continue
		}
		k = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, k)
		if len(k) > 40 {
			k = k[:40]
		}
		out = append(out, NamedPath{Name: k, Value: v})
	}
	return out
}

// Config is the collector's inputs, all from the operator's environment.
type Config struct {
	StoragePaths     []NamedPath
	BackupStatusFile string
	TLSCertFiles     []NamedPath
	// SensorCAFile is the sensor CA's PEM file (the certificate is read,
	// never the key it may sit beside).
	SensorCAFile     string
	WebHealthURL     string
	GatewayHealthURL string
}

// Deps are the live reads the collector needs.
type Deps struct {
	PingDB       func(ctx context.Context) error
	DatabaseSize func(ctx context.Context) (int64, error)
	PingRedis    func(ctx context.Context) error // nil: not configured
	// Sensors returns the count of active sensors and how many are online.
	Sensors func(ctx context.Context) (total, online int64, err error)
	// VersionCheck returns the version-check result; nil: not wired.
	VersionCheck func(ctx context.Context) (VersionCheck, error)
	RunningVer   func() (version, channel string)
	HTTP         *http.Client
	Now          func() time.Time
}

// Collector builds snapshots.
type Collector struct {
	cfg Config
	d   Deps
}

func newProbeClient() *http.Client { return httpsec.InternalProbeClient(probeTimeout) }

// New creates a collector.
func New(cfg Config, d Deps) *Collector {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.HTTP == nil {
		d.HTTP = newProbeClient()
	}
	return &Collector{cfg: cfg, d: d}
}

// Collect reads every check. It never returns an error: a failing check is
// reported in the snapshot.
func (c *Collector) Collect(ctx context.Context) Snapshot {
	now := c.d.Now().UTC()
	s := Snapshot{CheckedAt: now, Services: []Service{}, Certificates: []Certificate{}}

	s.Services = append(s.Services,
		Service{Name: "api", Configured: true, OK: true},
		c.probe(ctx, "postgres", c.d.PingDB),
		c.probe(ctx, "redis", c.d.PingRedis),
		c.httpProbe(ctx, "web", c.cfg.WebHealthURL),
		c.httpProbe(ctx, "gateway", c.cfg.GatewayHealthURL))
	sensors := Service{Name: "sensors", Configured: c.d.Sensors != nil, OK: true}
	if c.d.Sensors != nil {
		total, online, err := c.d.Sensors(ctx)
		if err != nil {
			sensors.OK, sensors.Code = false, CodeUnreadable
		} else {
			sensors.Detail = online
			// No sensors at all is not a fault; every one offline is.
			sensors.OK = total == 0 || online > 0
			if !sensors.OK {
				sensors.Code = CodeUnhealthy
			}
		}
	}
	s.Services = append(s.Services, sensors)

	s.Storage = c.storage(ctx)
	s.Backup = c.backup(now)
	s.Certificates = c.certificates(now)
	s.Version = c.version(ctx)

	s.Level = s.maxLevel()
	return s
}

func (s Snapshot) maxLevel() int {
	lv := LevelOK
	up := func(l int) {
		if l > lv {
			lv = l
		}
	}
	for _, v := range s.Storage.Volumes {
		up(v.Level)
	}
	up(s.Backup.Level)
	for _, ce := range s.Certificates {
		up(ce.Level)
	}
	for _, sv := range s.Services {
		if sv.Configured && !sv.OK {
			up(LevelCritical)
		}
	}
	return lv
}

func (c *Collector) probe(ctx context.Context, name string, f func(context.Context) error) Service {
	if f == nil {
		return Service{Name: name}
	}
	start := time.Now()
	err := f(ctx)
	sv := Service{Name: name, Configured: true, OK: err == nil, LatencyMS: float64(time.Since(start).Microseconds()) / 1000}
	if err != nil {
		sv.Code = CodeUnreachable
	}
	return sv
}

// httpProbe sends one GET to an operator-configured health URL: no redirects,
// a short timeout, the body discarded.
func (c *Collector) httpProbe(ctx context.Context, name, url string) Service {
	if url == "" {
		return Service{Name: name}
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	sv := Service{Name: name, Configured: true}
	if err != nil {
		sv.Code = CodeUnreachable
		return sv
	}
	start := time.Now()
	resp, err := c.d.HTTP.Do(req)
	sv.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		sv.Code = CodeUnreachable
		return sv
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		sv.Code = CodeUnhealthy
		return sv
	}
	sv.OK = true
	return sv
}

func (c *Collector) storage(ctx context.Context) Storage {
	st := Storage{Volumes: []Volume{}}
	for _, p := range c.cfg.StoragePaths {
		v := Volume{Name: p.Name}
		total, avail, err := diskUsage(p.Value)
		if err == nil && total > 0 {
			v.OK, v.TotalB, v.FreeB = true, total, avail
			v.UsedB = total - min(avail, total)
			v.FreeRatio = float64(avail) / float64(total)
			v.Level = storageLevel(v.FreeRatio)
		}
		st.Volumes = append(st.Volumes, v)
	}
	if c.d.DatabaseSize != nil {
		if n, err := c.d.DatabaseSize(ctx); err == nil {
			st.DatabaseB, st.DatabaseOK = n, true
		}
	}
	return st
}

func storageLevel(free float64) int {
	switch {
	case free < StorageCriticalFreeRatio:
		return LevelCritical
	case free < StorageWarnFreeRatio:
		return LevelWarning
	}
	return LevelOK
}

func (c *Collector) backup(now time.Time) Backup {
	b := Backup{}
	if c.cfg.BackupStatusFile == "" {
		return b
	}
	raw, ok := readBounded(c.cfg.BackupStatusFile)
	if !ok {
		return b
	}
	ts, exit, found := parseBackupStatus(raw)
	if exit > 0 {
		b.LastFailed = true
	}
	if !found {
		return b
	}
	t := time.Unix(ts, 0).UTC()
	b.Reported, b.LastSuccess = true, &t
	if age := now.Sub(t); age > 0 {
		b.AgeSeconds = int64(age.Seconds())
	}
	if now.Sub(t) > BackupMaxAge {
		b.Level = LevelWarning
	}
	return b
}

// parseBackupStatus reads the two lines the backup job writes (monitoring
// guide, BackupStale). exit is -1 when absent.
func parseBackupStatus(raw []byte) (ts int64, exit int64, found bool) {
	exit = -1
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		v, err := strconv.ParseFloat(f[1], 64)
		if err != nil || v < 0 {
			continue
		}
		switch f[0] {
		case backupMetric:
			ts, found = int64(v), v > 0
		case backupExitCode:
			exit = int64(v)
		}
	}
	return ts, exit, found
}

func (c *Collector) certificates(now time.Time) []Certificate {
	out := []Certificate{}
	files := make([]NamedPath, 0, len(c.cfg.TLSCertFiles)+1)
	if c.cfg.SensorCAFile != "" {
		files = append(files, NamedPath{Name: "sensor-ca", Value: c.cfg.SensorCAFile})
	}
	files = append(files, c.cfg.TLSCertFiles...)
	for _, f := range files {
		ce := Certificate{Name: f.Name}
		if raw, ok := readBounded(f.Value); ok {
			if na, ok := firstCertExpiry(raw); ok {
				ce.OK, ce.NotAfter = true, na.UTC()
				left := na.Sub(now)
				ce.ExpiresInSecs = int64(left.Seconds())
				switch {
				case left < CertCriticalWithin:
					ce.Level = LevelCritical
				case left < CertWarnWithin:
					ce.Level = LevelWarning
				}
			}
		}
		out = append(out, ce)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// firstCertExpiry returns NotAfter of the first CERTIFICATE block; private
// key blocks in the same file are skipped unread.
func firstCertExpiry(raw []byte) (time.Time, bool) {
	for {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			return time.Time{}, false
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return time.Time{}, false
		}
		return cert.NotAfter, true
	}
}

// readBounded reads a regular file of at most maxFileBytes.
func readBounded(path string) ([]byte, bool) {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxFileBytes {
		return nil, false
	}
	b, err := os.ReadFile(path) //nolint:gosec // operator-configured path
	if err != nil || len(b) > maxFileBytes {
		return nil, false
	}
	return b, true
}

func (c *Collector) version(ctx context.Context) Version {
	v := Version{}
	if c.d.RunningVer != nil {
		v.Running, v.Channel = c.d.RunningVer()
	}
	if c.d.VersionCheck != nil {
		if vc, err := c.d.VersionCheck(ctx); err == nil {
			v.Check = &vc
		}
	}
	return v
}
