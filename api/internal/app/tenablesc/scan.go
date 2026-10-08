package tenablesc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scan launch limits.
const (
	DefaultMaxScanSeconds = 8 * 3600
	MinMaxScanSeconds     = 600
	MaxMaxScanSeconds     = 72 * 3600
	// scanImportGrace is how long past max_scan_seconds the command may live
	// (the result import and the pull of its findings).
	scanImportGrace = 2 * time.Hour
	// MaxScanTargets bounds the targets of one connector_scan command; the
	// sensor applies its own (usually smaller) max_targets_per_scan.
	MaxScanTargets = 10000
)

// ScanConfig is the scanner_config of an OpenCTEM scan whose scanner is
// tenable_sc: which connector integration launches it, and with which
// Tenable.sc scan policy, repository and zone.
type ScanConfig struct {
	IntegrationID  shared.ID
	PolicyID       int
	RepositoryID   int
	ZoneID         int
	MaxScanSeconds int
}

// ParseScanConfig validates a tenable_sc scan's scanner_config.
func ParseScanConfig(cfg map[string]any) (ScanConfig, error) {
	var out ScanConfig
	id, err := shared.IDFromString(stringValue(cfg["integration_id"]))
	if err != nil {
		return out, invalid("scanner_config.integration_id must name a Tenable.sc connector integration")
	}
	out.IntegrationID = id
	positive := func(key string, required bool) (int, error) {
		v, ok, err := intValue(cfg[key])
		switch {
		case err != nil:
			return 0, invalid(fmt.Sprintf("scanner_config.%s must be a number", key))
		case !ok && required:
			return 0, invalid(fmt.Sprintf("scanner_config.%s is required", key))
		case ok && v <= 0 && required:
			return 0, invalid(fmt.Sprintf("scanner_config.%s must be a positive Tenable.sc id", key))
		case ok && v < 0:
			return 0, invalid(fmt.Sprintf("scanner_config.%s must not be negative", key))
		}
		return v, nil
	}
	if out.PolicyID, err = positive("policy_id", true); err != nil {
		return out, err
	}
	if out.RepositoryID, err = positive("repository_id", true); err != nil {
		return out, err
	}
	if out.ZoneID, err = positive("zone_id", false); err != nil {
		return out, err
	}
	if out.MaxScanSeconds, err = positive("max_scan_seconds", false); err != nil {
		return out, err
	}
	if out.MaxScanSeconds == 0 {
		out.MaxScanSeconds = DefaultMaxScanSeconds
	}
	if out.MaxScanSeconds < MinMaxScanSeconds || out.MaxScanSeconds > MaxMaxScanSeconds {
		return out, invalid(fmt.Sprintf("scanner_config.max_scan_seconds must be between %d and %d", MinMaxScanSeconds, MaxMaxScanSeconds))
	}
	return out, nil
}

// ScanPayload is the connector_scan command payload (RFC-047 §5.2), plus the
// scan workflow bookkeeping keys the platform reads back on completion.
type ScanPayload struct {
	Scanner        string   `json:"scanner"`
	Instance       string   `json:"instance"`
	IntegrationID  string   `json:"integration_id"`
	Targets        []string `json:"targets"`
	PolicyID       int      `json:"policy_id"`
	RepositoryID   int      `json:"repository_id"`
	ZoneID         int      `json:"zone_id,omitempty"`
	MaxScanSeconds int      `json:"max_scan_seconds"`
	MinSeverity    int      `json:"min_severity"`

	RunID     string `json:"run_id,omitempty"`
	ScanID    string `json:"scan_id,omitempty"`
	ScanRunID string `json:"scan_run_id,omitempty"`
	StepKey   string `json:"step_key,omitempty"`
	StepRunID string `json:"scan_run_step_id,omitempty"`
}

// connectorFor loads a tenant's connector integration and validates the scan
// config against it: an enabled connector, its sensor one of the tenant's own,
// and the policy, repository and zone inside the catalog the sensor reported
// (when it reported one; the sensor enforces its allow-list either way).
func (s *Service) connectorFor(ctx context.Context, tenantID shared.ID, sc ScanConfig) (*integration.Integration, ConnectorConfig, error) {
	intg, err := s.integrations.GetByTenantAndID(ctx, tenantID, sc.IntegrationID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, ConnectorConfig{}, invalid("scanner_config.integration_id names no integration of this organization")
		}
		return nil, ConnectorConfig{}, err
	}
	cc, err := ParseConnectorConfig(intg)
	if err != nil {
		if errors.Is(err, ErrNotConnector) {
			return nil, cc, invalid("scanner_config.integration_id is not a Tenable.sc sensor connector")
		}
		return nil, cc, err
	}
	if intg.Status() == integration.StatusDisabled {
		return nil, cc, ErrDisabled
	}
	if err := s.ValidateConnector(ctx, tenantID, intg.Config()); err != nil {
		return nil, cc, err
	}
	cat := readState(intg).Catalog
	if cat != nil {
		if len(cat.Policies) > 0 && !cat.hasPolicy(sc.PolicyID) {
			return nil, cc, invalid(fmt.Sprintf("Tenable.sc policy %d is not allowed by the sensor owner", sc.PolicyID))
		}
		if len(cat.ScanRepositories) > 0 && !catalogHas(cat.ScanRepositories, sc.RepositoryID) {
			return nil, cc, invalid(fmt.Sprintf("Tenable.sc repository %d is not allowed for scans by the sensor owner", sc.RepositoryID))
		}
		if sc.ZoneID != 0 && len(cat.ScanZones) > 0 && !catalogHas(cat.ScanZones, sc.ZoneID) {
			return nil, cc, invalid(fmt.Sprintf("Tenable.sc zone %d is not allowed by the sensor owner", sc.ZoneID))
		}
	}
	return intg, cc, nil
}

// ValidateScanConfig checks a tenable_sc scan's scanner_config when the scan
// is created or updated (tenant-scoped: another tenant's integration is not
// found).
func (s *Service) ValidateScanConfig(ctx context.Context, tenantID shared.ID, cfg map[string]any) error {
	sc, err := ParseScanConfig(cfg)
	if err != nil {
		return err
	}
	_, _, err = s.connectorFor(ctx, tenantID, sc)
	return err
}

// NewScanCommand builds the connector_scan command for targets that already
// passed the active-probe gate and the caller's scope. The command is pinned
// to the connector's sensor, which must be active and run the connector now.
// The caller stores it.
func (s *Service) NewScanCommand(ctx context.Context, tenantID shared.ID, cfg map[string]any, targets []string,
	bk map[string]string) (*command.Command, error) {
	sc, err := ParseScanConfig(cfg)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, invalid("no target to scan")
	}
	if len(targets) > MaxScanTargets {
		return nil, invalid(fmt.Sprintf("at most %d targets per Tenable.sc scan", MaxScanTargets))
	}
	_, cc, err := s.connectorFor(ctx, tenantID, sc)
	if err != nil {
		return nil, err
	}
	sn, err := s.sensors.GetByTenantAndID(ctx, tenantID, cc.SensorID)
	if err != nil {
		return nil, err
	}
	if !SensorRunsConnector(sn) {
		return nil, ErrSensorUnavailable
	}
	payload, err := json.Marshal(ScanPayload{
		Scanner: ToolName, Instance: cc.Instance, IntegrationID: sc.IntegrationID.String(),
		Targets: slices.Clone(targets), PolicyID: sc.PolicyID, RepositoryID: sc.RepositoryID, ZoneID: sc.ZoneID,
		MaxScanSeconds: sc.MaxScanSeconds, MinSeverity: cc.MinSeverity,
		RunID: bk["run_id"], ScanID: bk["scan_id"], ScanRunID: bk["scan_run_id"],
		StepKey: bk["step_key"], StepRunID: bk["scan_run_step_id"],
	})
	if err != nil {
		return nil, fmt.Errorf("encode connector_scan payload: %w", err)
	}
	cmd, err := command.NewCommand(tenantID, command.CommandTypeConnectorScan, command.CommandPriorityNormal, payload)
	if err != nil {
		return nil, err
	}
	cmd.SetSensorID(sn.ID)
	cmd.SetExpiration(s.now().UTC().Add(time.Duration(sc.MaxScanSeconds)*time.Second + scanImportGrace))
	// The targets passed the full gate at t1 and run outside every scan
	// zone on the pinned connector sensor; the claim re-checks them so. A
	// scan run adds its actor's act scope (scan.triggerConnectorScan).
	cmd.DispatchGate = &command.DispatchGate{Tier: 1, Validated: true, NoZoneRouting: true}
	return cmd, nil
}

// Catalog is what the sensor reported it allows (connector_sync result
// metadata "catalog"): names for the pickers, restricted to its allow-lists.
type Catalog struct {
	Repositories     []CatalogItem `json:"repositories,omitempty"`
	ScanRepositories []CatalogItem `json:"scan_repositories,omitempty"`
	Policies         []CatalogItem `json:"policies,omitempty"`
	ScanZones        []CatalogItem `json:"scan_zones,omitempty"`
}

// CatalogItem is one Tenable.sc object the sensor allows.
type CatalogItem struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func (c *Catalog) hasPolicy(id int) bool { return catalogHas(c.Policies, id) }

func catalogHas(items []CatalogItem, id int) bool {
	for _, it := range items {
		if it.ID == id {
			return true
		}
	}
	return false
}

// maxCatalogItems bounds each catalog list kept from a sensor report.
const maxCatalogItems = 500

// parseCatalog reads the untrusted catalog of a sync result: ids positive,
// names capped, lists bounded.
func parseCatalog(v any) *Catalog {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	list := func(key string) []CatalogItem {
		raw, ok := m[key].([]any)
		if !ok {
			return nil
		}
		var out []CatalogItem
		for _, r := range raw {
			if len(out) >= maxCatalogItems {
				break
			}
			im, ok := r.(map[string]any)
			if !ok {
				continue
			}
			id, ok, err := intValue(im["id"])
			if err != nil || !ok || id <= 0 {
				continue
			}
			out = append(out, CatalogItem{ID: id, Name: capText(stringValue(im["name"]), 128)})
		}
		return out
	}
	c := &Catalog{
		Repositories: list("repositories"), ScanRepositories: list("scan_repositories"),
		Policies: list("policies"), ScanZones: list("scan_zones"),
	}
	if c.Repositories == nil && c.ScanRepositories == nil && c.Policies == nil && c.ScanZones == nil {
		return nil
	}
	return c
}
