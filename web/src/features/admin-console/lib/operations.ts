import type { AdminOperations, AdminSensorTransport } from '../types'

/** Compares two versions like v0.9.2 / 0.10.0-rc.1 by their numeric core. */
export function compareVersions(a: string, b: string): number {
  const core = (v: string) =>
    v
      .replace(/^v/, '')
      .split(/[-+]/)[0]
      .split('.')
      .map((n) => Number.parseInt(n, 10) || 0)
  const x = core(a)
  const y = core(b)
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0)
    if (d !== 0) return d < 0 ? -1 : 1
  }
  return 0
}

export interface SensorFleetSummary {
  platform: { total: number; online: number; unhealthy: number }
  customer: { total: number; online: number; unhealthy: number }
  /** SDK versions in the field, newest first, with whether each is below the minimum. */
  versions: { version: string; count: number; advisory: boolean }[]
}

const UNHEALTHY = new Set(['offline', 'stale', 'error'])

/** Active sensors grouped for the Operations page (counts only). */
export function summarizeSensors(o: AdminOperations): SensorFleetSummary {
  const out: SensorFleetSummary = {
    platform: { total: 0, online: 0, unhealthy: 0 },
    customer: { total: 0, online: 0, unhealthy: 0 },
    versions: [],
  }
  const versions = new Map<string, number>()
  for (const s of o.sensors) {
    const g = s.platform ? out.platform : out.customer
    g.total += s.count
    if (s.health === 'online') g.online += s.count
    if (UNHEALTHY.has(s.health)) g.unhealthy += s.count
    const v = s.sdk_version || 'unknown'
    versions.set(v, (versions.get(v) ?? 0) + s.count)
  }
  out.versions = [...versions.entries()]
    .map(([version, count]) => ({
      version,
      count,
      // An SDK release with a published security advisory.
      advisory:
        version !== 'unknown' &&
        (o.sdk_advisories ?? []).some((a) => compareVersions(version, a) === 0),
    }))
    .sort((a, b) =>
      a.version === 'unknown'
        ? 1
        : b.version === 'unknown'
          ? -1
          : compareVersions(b.version, a.version)
    )
  return out
}

export type SchemaState = 'ok' | 'behind' | 'ahead' | 'dirty' | 'unknown'

export function schemaState(o: AdminOperations): SchemaState {
  if (!o.schema.known) return 'unknown'
  if (o.schema.dirty) return 'dirty'
  if (o.schema.shipped > 0 && o.schema.applied < o.schema.shipped) return 'behind'
  if (o.schema.shipped > 0 && o.schema.applied > o.schema.shipped) return 'ahead'
  return 'ok'
}

/** Probe reasons with their own explanation (api sensortransport/probe.go). */
const TRANSPORT_REASONS = new Set([
  'transport_off',
  'no_public_host',
  'sensor_ca_unavailable',
  'listener_failed',
  'dns_failed',
  'unreachable',
  'foreign_certificate',
  'handshake_failed',
  'http2_refused',
  'probe_pending',
])

export interface SensorTransportView {
  /** What sensors use: grpc (offered, HTTPS too), https, pending, off (v2). */
  binding: 'grpc' | 'https' | 'pending' | 'off'
  /** The i18n key of the note, set only when an operator can change something. */
  noteKey?: string
  /** The raw reason code, a secondary detail next to the note. */
  reason?: string
}

/**
 * How sensors reach this installation, for Console > Operations. HTTPS is a
 * normal, signed binding, not a fault: the note says what would let sensors
 * use gRPC, and only when the probe gave a reason (not while it runs).
 */
export function sensorTransportView(st?: AdminSensorTransport): SensorTransportView | null {
  if (!st) return null
  if (st.mode === 'off') {
    return {
      binding: 'off',
      noteKey: 'admin.ops.transport.reason.transport_off',
      reason: 'transport_off',
    }
  }
  if (st.grpc.state === 'advertised') return { binding: 'grpc' }
  if (st.grpc.state === 'pending' || st.grpc.reason === 'probe_pending') {
    return { binding: 'pending' }
  }
  const reason = st.grpc.reason || undefined
  const known = reason && TRANSPORT_REASONS.has(reason)
  return {
    binding: 'https',
    noteKey: `admin.ops.transport.reason.${known ? reason : 'other'}`,
    reason,
  }
}
