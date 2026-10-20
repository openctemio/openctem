package command

import (
	"encoding/json"
	"slices"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// A command the sensor cannot take for a missing feature names that
// feature: a tenant-only rule sources job waits for a sensor that honors
// rule sources, not for a confined one.
func TestMissingFeatureReasonsNameTheFeature(t *testing.T) {
	cmdWith := func(features ...string) *commanddom.Command {
		raw, _ := json.Marshal(map[string]any{commanddom.PayloadKeyRequiredFeatures: features})
		return &commanddom.Command{Payload: raw}
	}
	sensorWith := func(caps ...string) *sensordom.Sensor {
		return &sensordom.Sensor{Reported: sensordom.CapabilityReport{Capabilities: caps}}
	}
	cases := []struct {
		name string
		cmd  *commanddom.Command
		sn   *sensordom.Sensor
		want []string
	}{
		{"rule sources missing", cmdWith(sensordom.CapabilityRuleSources), sensorWith(), []string{commanddom.PlacementRuleSourcesUnsupported}},
		{"confinement missing", cmdWith(sensordom.CapabilityNetConfined), sensorWith(sensordom.CapabilityRuleSources), []string{commanddom.PlacementNotConfined}},
		{"only the missing one", cmdWith(sensordom.CapabilityNetConfined, sensordom.CapabilityRuleSources), sensorWith(sensordom.CapabilityNetConfined), []string{commanddom.PlacementRuleSourcesUnsupported}},
		{"both missing", cmdWith(sensordom.CapabilityNetConfined, sensordom.CapabilityRuleSources), nil, []string{commanddom.PlacementNotConfined, commanddom.PlacementRuleSourcesUnsupported}},
		{"nothing readable", &commanddom.Command{}, nil, []string{commanddom.PlacementNotConfined}},
	}
	for _, c := range cases {
		if got := missingFeatureReasons(c.cmd, c.sn); !slices.Equal(got, c.want) {
			t.Errorf("%s: reasons = %v, want %v", c.name, got, c.want)
		}
	}
}
