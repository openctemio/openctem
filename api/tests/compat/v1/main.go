// Command compat-v1 drives the sensor protocol v1 with the last released
// sdk-go, exactly as a sensor already deployed in the field does, against an
// API under test. Every step must succeed; any failure exits non-zero.
//
// The API, tenant, sensor key and queued command are prepared by
// scripts/compat-v1.sh, which passes them in through the environment.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/platform"
)

type harness struct {
	ctx     context.Context
	cli     *client.Client
	baseURL string
	agentID string
	apiKey  string
	failed  int
}

func main() {
	h := &harness{
		baseURL: mustEnv("COMPAT_API_URL"),
		agentID: mustEnv("COMPAT_AGENT_ID"),
		apiKey:  mustEnv("COMPAT_API_KEY"),
	}
	commandID := mustEnv("COMPAT_COMMAND_ID")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h.ctx = ctx

	cfg := client.DefaultConfig()
	cfg.BaseURL = h.baseURL
	cfg.APIKey = h.apiKey
	cfg.AgentID = h.agentID
	cfg.MaxRetries = 1
	cfg.RetryDelay = time.Second
	h.cli = client.New(cfg)

	h.step("connection test", func() error { return h.cli.TestConnection(ctx) })
	h.step("heartbeat", h.heartbeat)
	h.step("push findings and assets", h.push)
	h.step("command lifecycle (poll, ack, start, progress, complete)", func() error {
		return h.commandLifecycle(commandID)
	})
	h.step("fetch suppression rules", func() error {
		_, err := h.cli.GetSuppressions(ctx)
		return err
	})
	h.step("renew key, then use the new key", h.renewKey)

	if h.failed > 0 {
		fmt.Printf("\nFAIL: %d protocol-v1 step(s) failed against %s\n", h.failed, h.baseURL)
		os.Exit(1)
	}
	fmt.Println("\nPASS: every protocol-v1 step succeeded")
}

func (h *harness) step(name string, fn func() error) {
	if err := fn(); err != nil {
		h.failed++
		fmt.Printf("[FAIL] %s: %v\n", name, err)
		return
	}
	fmt.Printf("[PASS] %s\n", name)
}

func (h *harness) heartbeat() error {
	return h.cli.SendHeartbeat(h.ctx, &core.AgentStatus{
		Name:     "compat-v1",
		Status:   core.AgentStateRunning,
		Scanners: []string{"nuclei"},
		Message:  "protocol v1 compatibility run",
	})
}

func (h *harness) push() error {
	report := ctis.NewReport()
	report.Tool = &ctis.Tool{Name: "nuclei", Version: "3.0.0"}
	report.Assets = []ctis.Asset{{ID: "a1", Type: ctis.AssetTypeDomain, Value: "compat-v1.example.com"}}
	report.Findings = []ctis.Finding{{
		Type:     ctis.FindingTypeVulnerability,
		Title:    "Protocol v1 compatibility finding",
		Severity: ctis.SeverityMedium,
		RuleID:   "compat-v1-rule",
		AssetRef: "a1",
	}}
	res, err := h.cli.PushFindings(h.ctx, report)
	if err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("push not successful: %s", res.Message)
	}
	if res.FindingsCreated+res.FindingsUpdated < 1 {
		return fmt.Errorf("no finding stored: %+v", res)
	}
	return nil
}

func (h *harness) commandLifecycle(commandID string) error {
	cmds, err := h.cli.PollCommands(h.ctx, 10)
	if err != nil {
		return fmt.Errorf("poll: %w", err)
	}
	if !slices.ContainsFunc(cmds, func(c client.Command) bool { return c.ID == commandID }) {
		return fmt.Errorf("poll did not return the queued command %s (got %d commands)", commandID, len(cmds))
	}
	if err := h.cli.AcknowledgeCommand(h.ctx, commandID); err != nil {
		return fmt.Errorf("ack: %w", err)
	}
	if err := h.cli.StartCommand(h.ctx, commandID); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	if err := h.cli.ReportCommandProgress(h.ctx, commandID, 50, "half way"); err != nil {
		return fmt.Errorf("progress: %w", err)
	}
	result, _ := json.Marshal(map[string]any{"status": "ok"})
	if err := h.cli.CompleteCommand(h.ctx, commandID, result); err != nil {
		return fmt.Errorf("complete: %w", err)
	}
	return nil
}

func (h *harness) renewKey() error {
	pc := platform.NewPlatformClient(&platform.ClientConfig{
		BaseURL: h.baseURL,
		APIKey:  h.apiKey,
		AgentID: h.agentID,
	})
	resp, err := pc.RenewKey(h.ctx)
	if err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	if resp.APIKey == "" || resp.APIKey == h.apiKey {
		return fmt.Errorf("renew returned no new key")
	}
	h.cli.SetAPIKey(resp.APIKey)
	if err := h.heartbeat(); err != nil {
		return fmt.Errorf("heartbeat with renewed key: %w", err)
	}
	return nil
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		fmt.Fprintf(os.Stderr, "missing required environment variable %s\n", name)
		os.Exit(2)
	}
	return v
}
