/**
 * Which of a scan's targets cover the core infrastructure its sensors depend
 * on: their DNS resolvers, gateways, their own addresses and the platform's
 * addresses, as the sensors reported them (GET /sensors/core-addresses). An
 * intrusive scan of a sensor's resolver or gateway can cut that sensor off
 * the platform, so the form warns (it never blocks). Address and CIDR
 * targets only: the platform does not resolve names.
 */

import type { SensorCoreAddressesResponse, SensorCoreAddressRole } from '@/lib/api/sensor-types'
import { formatAddr, parseAddr, rangesContain } from '@/features/scan-zones/lib/ranges'

export interface CoreInfraHit {
  address: string
  /** Each sensor and role the address is, in report order. */
  uses: { sensorName: string; role: SensorCoreAddressRole }[]
}

/** Most hits listed (the rest are counted by the caller). */
export const MAX_CORE_INFRA_HITS = 50

export function coreInfraHits(
  targets: readonly string[],
  report: SensorCoreAddressesResponse | undefined | null
): CoreInfraHit[] {
  if (!report?.items?.length || targets.length === 0) return []
  const ranges = targets.filter((t) => /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(t.trim()))
  if (ranges.length === 0) return []
  const byAddr = new Map<string, CoreInfraHit>()
  for (const item of report.items) {
    for (const a of item.addresses ?? []) {
      const parsed = parseAddr(a.address)
      if (!parsed) continue
      const address = formatAddr(parsed)
      if (!rangesContain(ranges, address)) continue
      let hit = byAddr.get(address)
      if (!hit) {
        if (byAddr.size >= MAX_CORE_INFRA_HITS) continue
        hit = { address, uses: [] }
        byAddr.set(address, hit)
      }
      if (!hit.uses.some((u) => u.sensorName === item.sensor_name && u.role === a.role)) {
        hit.uses.push({ sensorName: item.sensor_name, role: a.role })
      }
    }
  }
  return [...byAddr.values()]
}
