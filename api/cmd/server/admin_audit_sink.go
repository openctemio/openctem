package main

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/auditsink"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// startAdminAuditSink streams the administrators' audit log off the box when
// ADMIN_AUDIT_SINK is set: every row with its chain position and hash, and
// the chain head every ADMIN_AUDIT_SINK_HEAD_INTERVAL. It returns a stop
// function (flushes what is queued). A bad destination stops the start-up:
// an operator who asked for an off-box copy must not silently run without.
func startAdminAuditSink(ctx context.Context, cfg config.AdminAuditSinkConfig, repo *postgres.AuditLogRepository, log *logger.Logger) (func(), error) {
	if cfg.URL == "" {
		return func() {}, nil
	}
	sink, err := auditsink.New(cfg.URL, cfg.Token)
	if err != nil {
		return nil, err
	}
	interval := cfg.HeadInterval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	f := auditsink.NewForwarder(sink, log)
	repo.SetAfterCreate(f.Row)
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		f.Run(sctx)
		close(done)
	}()
	go f.ExportHead(sctx, repo.ChainHead, interval)
	log.Info("administrators' audit log streamed off the box", "sink", redactSinkURL(cfg.URL), "head_interval", interval.String())
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	}, nil
}

// redactSinkURL keeps the scheme and host of the sink for the log line.
func redactSinkURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(invalid)"
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}
