package command

// Shared jobs (docs/rfcs/RFC-100-shared-sensors.md): commands queued for the
// instance's shared sensors (is_platform_job). Only a shared sensor claims
// them, through the shared claim path; an organization sensor never does.

// PayloadKeyPreferredRegion names the region of shared sensors a shared job
// must run from (sensors.region). A job without it runs from any region.
const PayloadKeyPreferredRegion = "preferred_region"

// CapabilitySharedIsolation is what a shared sensor reports once it runs
// every job in its own sandbox, network namespace and egress policy (the
// sdk-go shared isolation profile). It is matched against what the sensor
// reported, never against an administrator's list: a shared sensor that
// does not report it is handed no shared job.
const CapabilitySharedIsolation = "shared.isolation@1"
