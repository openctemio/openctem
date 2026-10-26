/**
 * A sensor whose owner set SENSOR_SCAN_EGRESS=direct-only reports this
 * marker (sdk-go core.CapabilityEgressHostDirect): it runs its scans direct
 * and takes no pool.
 */
export const CAP_HOST_DIRECT = 'egress.host-direct@1'

export function isHostDirect(capabilities: string[] | null | undefined): boolean {
  return (capabilities ?? []).includes(CAP_HOST_DIRECT)
}

/**
 * What a host direct-only sensor's network path means:
 * - 'direct-host': it inherits the default pool (or goes Direct): its scans
 *   run direct, set on the sensor host;
 * - 'host-conflict': a pool is chosen for it, and its host refuses pools:
 *   its scan jobs wait (the platform never sends them direct).
 */
export type HostDirectState = 'direct-host' | 'host-conflict'

export function hostDirectState(
  value: string,
  capabilities: string[] | null | undefined
): HostDirectState | null {
  if (!isHostDirect(capabilities)) return null
  return value.startsWith('pool:') ? 'host-conflict' : 'direct-host'
}
