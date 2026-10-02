package legacyv1

// RenamedEnv maps the API server's pre-sensor environment variables to their
// replacements. They live in operators' .env files, compose files and the
// Helm chart's API env, so an upgrade must keep working with the old names:
// config.Load reads the new name first, falls back to the old one with a
// startup deprecation warning, and refuses to start only when both are set to
// different values (RFC-023 §9.5, "Upgrade migration for existing
// installations").
var RenamedEnv = []struct{ Old, New string }{
	{"AGENT_CONFIG_TEMPLATES_DIR", "SENSOR_CONFIG_TEMPLATES_DIR"},
	{"AGENT_PUBLIC_API_URL", "SENSOR_PUBLIC_API_URL"},
	{"AGENT_KEY_TTL", "SENSOR_KEY_TTL"},
	{"AGENT_LB_JOB_WEIGHT", "SENSOR_LB_JOB_WEIGHT"},
	{"AGENT_LB_CPU_WEIGHT", "SENSOR_LB_CPU_WEIGHT"},
	{"AGENT_LB_MEMORY_WEIGHT", "SENSOR_LB_MEMORY_WEIGHT"},
	{"AGENT_LB_DISK_IO_WEIGHT", "SENSOR_LB_DISK_IO_WEIGHT"},
	{"AGENT_LB_NETWORK_WEIGHT", "SENSOR_LB_NETWORK_WEIGHT"},
	{"AGENT_LB_MAX_DISK_THROUGHPUT_MBPS", "SENSOR_LB_MAX_DISK_THROUGHPUT_MBPS"},
	{"AGENT_LB_MAX_NETWORK_THROUGHPUT_MBPS", "SENSOR_LB_MAX_NETWORK_THROUGHPUT_MBPS"},
}

// Sensor config template directories. The default moved with the rename; an
// installation that mounted custom templates at the old path keeps them.
const (
	ConfigTemplatesDir       = "configs/sensor-templates"
	LegacyConfigTemplatesDir = "configs/agent-templates"
)
