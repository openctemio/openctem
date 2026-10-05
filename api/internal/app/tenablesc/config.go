// Package tenablesc is the platform side of the Tenable.sc sensor connector:
// it turns a Tenable integration into connector_sync commands for the sensor
// that holds the Tenable credentials, and follows those commands to keep the
// integration's sync state and incremental cursor.
//
// Design: docs/rfcs/RFC-047-tenable-sc-sensor-connector.md.
package tenablesc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ToolName is the connector's tool name: the sensor reports it, the command
// payload names it in "scanner", and its reports carry it as tool.name.
const ToolName = "tenable_sc"

// Config limits and defaults.
const (
	DefaultSyncIntervalMinutes = 360
	MinSyncIntervalMinutes     = 60
	DefaultFullSyncDays        = 7
	MaxFullSyncDays            = 90
	DefaultMinSeverity         = 1
	MaxRepositories            = 100
)

// instanceNameRE is the shape of an instance name: the label the sensor owner
// gave the Tenable.sc instance in the sensor's connector config.
var instanceNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

// ConnectorConfig is a Tenable integration's connector settings.
type ConnectorConfig struct {
	// SensorID is the sensor that runs the connector; it holds the Tenable
	// credentials. Required.
	SensorID shared.ID
	// Instance names the Tenable.sc instance in the sensor's connector config.
	Instance string
	// FullSyncDays is how often a full (unwindowed) sync runs.
	FullSyncDays int
	// MinSeverity is the lowest Tenable severity pulled (0 info .. 4 critical).
	MinSeverity int
	// Repositories optionally narrows the repositories the sensor reads; the
	// sensor reads only their intersection with its own allow-list.
	Repositories []int
}

// ErrNotConnector: the integration is not a Tenable.sc sensor connector.
var ErrNotConnector = shared.NewDomainError("NOT_A_CONNECTOR",
	"this integration is not a Tenable.sc sensor connector (engine tenable_sc, execution mode sensor)", shared.ErrValidation)

// IsConnector reports whether an integration is a Tenable.sc sensor connector
// (provider tenable, engine tenable_sc, execution mode sensor).
func IsConnector(intg *integration.Integration) bool {
	if intg == nil || intg.Provider() != integration.ProviderTenable {
		return false
	}
	tc, err := scancoverage.ParseTenableConfig(intg.Config())
	return err == nil && tc.Engine == scancoverage.EngineTenableSC && tc.ExecutionMode == scancoverage.ExecutionModeSensor
}

// ParseConnectorConfig reads and validates a connector integration's config.
func ParseConnectorConfig(intg *integration.Integration) (ConnectorConfig, error) {
	if !IsConnector(intg) {
		return ConnectorConfig{}, ErrNotConnector
	}
	return ParseConnectorConfigMap(intg.Config())
}

// ParseConnectorConfigMap validates a Tenable integration config as a
// Tenable.sc sensor connector: engine tenable_sc, execution mode sensor, and
// the connector settings. It is what create and update accept.
func ParseConnectorConfigMap(cfg map[string]any) (ConnectorConfig, error) {
	tc, err := scancoverage.ParseTenableConfig(cfg)
	if err != nil {
		return ConnectorConfig{}, invalid(err.Error())
	}
	if tc.Engine != scancoverage.EngineTenableSC || tc.ExecutionMode != scancoverage.ExecutionModeSensor {
		return ConnectorConfig{}, invalid("only the Tenable.sc sensor connector is supported: engine must be tenable_sc and execution_mode sensor (the Tenable credentials stay on the sensor)")
	}

	var out ConnectorConfig
	if tc.SensorID == "" {
		return out, invalid("sensor_id is required: the sensor that runs the Tenable.sc connector")
	}
	id, err := shared.IDFromString(tc.SensorID)
	if err != nil {
		return out, invalid("sensor_id is not a valid id")
	}
	out.SensorID = id

	out.Instance = strings.TrimSpace(stringValue(cfg["instance"]))
	if out.Instance == "" {
		out.Instance = "default"
	}
	if !instanceNameRE.MatchString(out.Instance) {
		return out, invalid("instance must be 1-63 lowercase letters, digits, '.', '_' or '-'")
	}

	out.FullSyncDays = DefaultFullSyncDays
	if v, ok, err := intValue(cfg["full_sync_days"]); err != nil {
		return out, invalid("full_sync_days must be a number")
	} else if ok {
		if v < 1 || v > MaxFullSyncDays {
			return out, invalid(fmt.Sprintf("full_sync_days must be between 1 and %d", MaxFullSyncDays))
		}
		out.FullSyncDays = v
	}

	out.MinSeverity = DefaultMinSeverity
	if v, ok, err := intValue(cfg["min_severity"]); err != nil {
		return out, invalid("min_severity must be a number")
	} else if ok {
		if v < 0 || v > 4 {
			return out, invalid("min_severity must be between 0 (info) and 4 (critical)")
		}
		out.MinSeverity = v
	}

	if raw, present := cfg["repositories"]; present && raw != nil {
		list, ok := raw.([]any)
		if !ok {
			return out, invalid("repositories must be a list of Tenable repository ids")
		}
		if len(list) > MaxRepositories {
			return out, invalid(fmt.Sprintf("at most %d repositories", MaxRepositories))
		}
		seen := map[int]bool{}
		for _, item := range list {
			v, ok, err := intValue(item)
			if err != nil || !ok || v <= 0 {
				return out, invalid("repositories must be positive Tenable repository ids")
			}
			if !seen[v] {
				seen[v] = true
				out.Repositories = append(out.Repositories, v)
			}
		}
	}
	return out, nil
}

func invalid(msg string) error {
	return shared.NewDomainError("INVALID_CONNECTOR_CONFIG", msg, shared.ErrValidation)
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

// intValue reads a JSON number (float64), an int or a numeric string. ok is
// false when v is nil.
func intValue(v any) (int, bool, error) {
	switch n := v.(type) {
	case nil:
		return 0, false, nil
	case float64:
		if n != float64(int(n)) {
			return 0, false, fmt.Errorf("not an integer")
		}
		return int(n), true, nil
	case int:
		return n, true, nil
	case int64:
		return int(n), true, nil
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil, err
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		return i, err == nil, err
	default:
		return 0, false, fmt.Errorf("unsupported type %T", v)
	}
}
