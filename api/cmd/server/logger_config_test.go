package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// LOG_LEVEL / LOG_FORMAT must apply outside APP_ENV=production too; they were
// ignored there (always debug + text).
func TestLoggerConfig_HonoursLogSettingsInEveryEnv(t *testing.T) {
	for _, env := range []string{"development", "staging", "production"} {
		t.Run(env, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.App.Env = env
			cfg.Log.Level = "warn"
			cfg.Log.Format = "json"

			lc := loggerConfig(cfg)
			var buf bytes.Buffer
			lc.Output = &buf
			log := logger.New(lc)

			if log.Enabled(context.Background(), slog.LevelInfo) {
				t.Errorf("info enabled with LOG_LEVEL=warn")
			}
			log.Warn("hello", "k", "v")
			line := strings.TrimSpace(buf.String())
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("LOG_FORMAT=json but output is not JSON: %q", line)
			}
			if m["msg"] != "hello" {
				t.Errorf("msg=%v", m["msg"])
			}
		})
	}
}

func TestLoggerConfig_Sampling(t *testing.T) {
	cfg := &config.Config{}
	cfg.App.Env = "development"
	cfg.Log.SamplingEnabled = true
	cfg.Log.SamplingThreshold = 7
	cfg.Log.SamplingRate = 0.5
	cfg.Log.ErrorSamplingRate = 1
	lc := loggerConfig(cfg)
	if !lc.Sampling.Enabled || lc.Sampling.Threshold != 7 || lc.Sampling.Rate != 0.5 {
		t.Errorf("sampling = %+v", lc.Sampling)
	}
}
