package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/systemstatus"
	"github.com/openctemio/openctem/api/internal/app/versioncheck"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/version"
)

// newSystemCollector wires the System page (RFC-114) to the API's own reads.
// pingRedis may be nil.
func newSystemCollector(cfg *config.Config, db *sql.DB, pingRedis func(ctx context.Context) error, vc *versioncheck.Service) *systemstatus.Collector {
	paths := systemstatus.ParseNamed(cfg.System.StoragePaths)
	if cfg.System.StoragePaths == "" {
		if cfg.Storage.Provider == "local" && cfg.Storage.LocalPath != "" {
			paths = append(paths, systemstatus.NamedPath{Name: "attachments", Value: cfg.Storage.LocalPath})
		}
		if d := cfg.SensorConfig.TransportV3.CADir; d != "" {
			paths = append(paths, systemstatus.NamedPath{Name: "sensor-ca", Value: d})
		}
	}
	caFile := cfg.SensorConfig.TransportV3.CACertFile
	if caFile == "" && cfg.SensorConfig.TransportV3.CADir != "" {
		caFile = filepath.Join(cfg.SensorConfig.TransportV3.CADir, "sensor-ca.pem")
	}
	d := systemstatus.Deps{
		PingDB: db.PingContext,
		DatabaseSize: func(ctx context.Context) (int64, error) {
			var n int64
			err := db.QueryRowContext(ctx, `SELECT pg_database_size(current_database())`).Scan(&n)
			return n, err
		},
		PingRedis: pingRedis,
		Sensors: func(ctx context.Context) (int64, int64, error) {
			ops, err := postgres.ReadOpsSnapshot(ctx, db)
			if err != nil {
				return 0, 0, err
			}
			var total, online int64
			for _, s := range ops.Sensors {
				total += s.Count
				if s.Health == "online" {
					online += s.Count
				}
			}
			return total, online, nil
		},
		RunningVer: func() (string, string) {
			v := version.Get()
			return v.Version, v.Channel
		},
	}
	if vc != nil {
		d.VersionCheck = func(ctx context.Context) (systemstatus.VersionCheck, error) {
			v, err := vc.View(ctx)
			if err != nil {
				return systemstatus.VersionCheck{}, err
			}
			return systemstatus.VersionCheck{
				Enabled: v.Enabled, Configured: v.Configured, LastAttemptAt: v.LastAttemptAt, LastError: v.LastError,
				AppliedAt: v.AppliedAt,
				Latest:    v.Latest, UpdateAvailable: v.UpdateAvailable, Advisories: len(v.Advisories),
				Severity: v.Severity, Stale: v.Stale,
			}, nil
		}
	}
	return systemstatus.New(systemstatus.Config{
		StoragePaths: paths, BackupStatusFile: cfg.System.BackupStatusFile,
		TLSCertFiles: systemstatus.ParseNamed(cfg.System.TLSCertFiles), SensorCAFile: caFile,
		WebHealthURL: cfg.System.WebHealthURL, GatewayHealthURL: cfg.System.GatewayHealthURL,
	}, d)
}

// systemMailer emails the active platform administrators about a degraded
// check through the system SMTP sender. Without SMTP the watcher's WARN line
// (alert=system_*) and the metrics are the alert.
type systemMailer struct {
	admins admin.Repository
	email  interface {
		IsConfigured() bool
		SendReport(ctx context.Context, tenantID string, to []string, subject, htmlBody string) error
	}
	appName string
	log     *logger.Logger
}

func (m systemMailer) NotifyAdmins(ctx context.Context, subject, body string) error {
	if m.email == nil || !m.email.IsConfigured() {
		return nil
	}
	list, err := m.admins.ListActive(ctx)
	if err != nil {
		return fmt.Errorf("list administrators: %w", err)
	}
	to := make([]string, 0, len(list))
	for _, a := range list {
		to = append(to, a.Email())
	}
	if len(to) == 0 {
		return nil
	}
	name := m.appName
	if name == "" {
		name = defaultAppName
	}
	subject = strings.NewReplacer("\r", "", "\n", "").Replace(fmt.Sprintf("[%s] %s", name, subject))
	go func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(c, "", to, subject, body); err != nil {
			m.log.Warn("system check email failed", "alert", "system_mail")
		}
	}()
	return nil
}
