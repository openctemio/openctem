import type { Sensor } from '@/lib/api/sensor-types'

import type {
  ProxyTestClass,
  ProxyTestEndpointResult,
  ProxyTestOutcome,
  ProxyTestStatus,
} from '../types'

/** The most sensors one test asks. */
export const MAX_TEST_SENSORS = 3

/** The capability of a sensor that serves proxy tests (sdk-go core.CapabilityProxyTest). */
export const CAP_PROXY_TEST = 'proxy.test@1'

const FINISHED: ProxyTestStatus[] = ['completed', 'failed', 'canceled', 'expired']

export function isFinished(status: ProxyTestStatus): boolean {
  return FINISHED.includes(status)
}

export function allFinished(items: Pick<ProxyTestOutcome, 'status'>[]): boolean {
  return items.length > 0 && items.every((i) => isFinished(i.status))
}

/**
 * The sensors a test may ask: active, online (or late) and reporting
 * proxy.test@1, which a sensor does only when it accepts platform proxy
 * pools. The API checks the same and refuses the rest.
 */
export function testableSensors(sensors: Sensor[]): Sensor[] {
  return sensors.filter(
    (s) =>
      s.status === 'active' &&
      (s.health === 'online' || s.health === 'late') &&
      (s.reported?.capabilities ?? []).includes(CAP_PROXY_TEST)
  )
}

/** Sensors that cannot run it, for the hint under the picker. */
export function untestableCount(sensors: Sensor[]): number {
  return sensors.length - testableSensors(sensors).length
}

/** Adds or removes id, never above the limit. */
export function toggleSensor(selected: string[], id: string): string[] {
  if (selected.includes(id)) return selected.filter((s) => s !== id)
  return selected.length >= MAX_TEST_SENSORS ? selected : [...selected, id]
}

/** The i18n key and English text of a failure class. */
export const CLASS_TEXT: Record<ProxyTestClass, { key: string; en: string }> = {
  proxy_down: { key: 'proxyPools.test.class.proxyDown', en: 'Proxy unreachable' },
  proxy_auth: { key: 'proxyPools.test.class.proxyAuth', en: 'Credentials refused' },
  target_unreachable: {
    key: 'proxyPools.test.class.targetUnreachable',
    en: 'Test page unreachable',
  },
  target_refused: {
    key: 'proxyPools.test.class.targetRefused',
    en: 'Proxy refused the connection',
  },
  echo_failed: { key: 'proxyPools.test.class.echoFailed', en: 'No answer from the test page' },
}

/** Exit addresses of the passing endpoints, for an allow-list. */
export function exitAddresses(results: ProxyTestEndpointResult[]): string[] {
  return [...new Set(results.filter((r) => r.ok && r.exit_ip).map((r) => r.exit_ip as string))]
}
