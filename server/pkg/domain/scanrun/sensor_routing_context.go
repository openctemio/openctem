package scanrun

// RunContextKeySensorRouting is the run-context key with the trigger-time
// decision between the tenant's sensors and shared platform sensors. The scan
// trigger writes it after its checks (internal targets, asset groups, proof
// of the targets, platform access); a value sent by a caller is removed
// before the run is created.
const RunContextKeySensorRouting = "sensor_routing"

// The sensor routing decisions of a run.
const (
	// SensorRoutingTenant: every command goes to the tenant's sensors.
	SensorRoutingTenant = "tenant"
	// SensorRoutingPlatform: every command goes to platform sensors.
	SensorRoutingPlatform = "platform"
	// SensorRoutingAuto: the run may use platform sensors (it passed the
	// checks); each step goes there only when no tenant sensor has its tool.
	SensorRoutingAuto = "auto"
)

// SensorRoutingFromContext returns the run's routing decision, or "" when
// the run has none (a run not started from a scan).
func SensorRoutingFromContext(runContext map[string]any) string {
	v, _ := runContext[RunContextKeySensorRouting].(string)
	switch v {
	case SensorRoutingTenant, SensorRoutingPlatform, SensorRoutingAuto:
		return v
	}
	return ""
}
