import type { Sensor, SensorUnhardenedReason } from '@/lib/api/sensor-types'

/**
 * A sensor's security posture (api RFC-040 §11.4): what the sensor reports
 * about its local policy, its platform TLS pin and its tool sandbox, and the
 * reasons the platform flags it. Existing sensors keep working; the console
 * only flags them with a short fix. Self-reported: display only.
 */

/** One reason a sensor is flagged, with the fix to show. */
export interface PostureIssue {
  reason: SensorUnhardenedReason
  /** i18n key and English fallback of the short label. */
  labelKey: string
  label: string
  /** i18n key and English fallback of the actionable fix. */
  fixKey: string
  fix: string
}

const ISSUES: Record<SensorUnhardenedReason, Omit<PostureIssue, 'reason'>> = {
  policy_none: {
    labelKey: 'sensors.posture.issue.policyNone',
    label: 'No local policy',
    fixKey: 'sensors.posture.fix.policyNone',
    fix: 'Install a local policy (the Local policy tab of the install commands).',
  },
  pin_none: {
    labelKey: 'sensors.posture.issue.pinNone',
    label: 'Platform CA not pinned',
    fixKey: 'sensors.posture.fix.pinNone',
    fix: 'Pin the platform CA with SENSOR_CA_FINGERPRINT.',
  },
  network_unenforced: {
    labelKey: 'sensors.posture.issue.networkUnenforced',
    label: 'Tools not network-confined',
    fixKey: 'sensors.posture.fix.networkUnenforced',
    fix: 'Tools run without network confinement: run with SENSOR_SANDBOX_NETWORK=required and the seccomp profile.',
  },
  bearer_key: {
    labelKey: 'sensors.posture.issue.bearerKey',
    label: 'Bearer key',
    fixKey: 'sensors.posture.fix.bearerKey',
    fix: 'Pair the sensor again with an enrollment token for a key-bound identity.',
  },
}

/** The reasons the platform flags the sensor, in the API's order. Unknown
 * reasons from a newer API are skipped. */
export function postureIssues(sensor: Pick<Sensor, 'posture'>): PostureIssue[] {
  const out: PostureIssue[] = []
  for (const reason of sensor.posture?.unhardened ?? []) {
    const issue = ISSUES[reason as SensorUnhardenedReason]
    if (issue && !out.some((i) => i.reason === reason)) {
      out.push({ reason: reason as SensorUnhardenedReason, ...issue })
    }
  }
  return out
}

/** Whether the sensor is flagged as unhardened. */
export function isUnhardened(sensor: Pick<Sensor, 'posture'>): boolean {
  return postureIssues(sensor).length > 0
}

/** A value of the posture block, with its tone. */
export interface PostureValue {
  labelKey: string
  label: string
  tone: 'ok' | 'warn' | 'muted'
}

/** The local policy as the posture block shows it. */
export function postureLocalPolicy(sensor: Pick<Sensor, 'posture'>): PostureValue {
  switch (sensor.posture?.local_policy) {
    case 'enforced':
      return { labelKey: 'sensors.posture.policy.enforced', label: 'Enforced', tone: 'ok' }
    case 'absent_required':
      return {
        labelKey: 'sensors.posture.policy.absentRequired',
        label: 'Missing (network jobs refused)',
        tone: 'warn',
      }
    case 'absent_legacy':
      return { labelKey: 'sensors.posture.policy.absentLegacy', label: 'None', tone: 'warn' }
    default:
      return { labelKey: 'sensors.posture.notReported', label: 'Not reported', tone: 'muted' }
  }
}

/** The platform TLS pin as the posture block shows it. */
export function posturePlatformPin(sensor: Pick<Sensor, 'posture'>): PostureValue {
  switch (sensor.posture?.platform_pin) {
    case 'fingerprint':
      return {
        labelKey: 'sensors.posture.pin.fingerprint',
        label: 'Pinned CA (fingerprint)',
        tone: 'ok',
      }
    case 'ca_file':
      return { labelKey: 'sensors.posture.pin.caFile', label: 'Private CA file', tone: 'ok' }
    case 'none':
      return {
        labelKey: 'sensors.posture.pin.none',
        label: 'System trust store only',
        tone: 'warn',
      }
    default:
      return { labelKey: 'sensors.posture.notReported', label: 'Not reported', tone: 'muted' }
  }
}

/** The tool sandbox's network confinement as the posture block shows it. */
export function postureNetwork(sensor: Pick<Sensor, 'posture'>): PostureValue {
  switch (sensor.posture?.network_enforced) {
    case true:
      return { labelKey: 'sensors.posture.network.enforced', label: 'Confined', tone: 'ok' }
    case false:
      return { labelKey: 'sensors.posture.network.unenforced', label: 'Not confined', tone: 'warn' }
    default:
      return { labelKey: 'sensors.posture.notReported', label: 'Not reported', tone: 'muted' }
  }
}
