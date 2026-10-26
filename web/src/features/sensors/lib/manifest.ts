/**
 * Sensor manifests (api RFC-033): what a sensor is, registered by the sensor
 * or derived by the platform from its heartbeat, kept per version. These
 * helpers diff two versions the way the API's manifest_changed event does
 * (content versions are left out: they have their own events) and word a
 * diff for the history and the activity timeline.
 */

import type {
  SensorManifestDiff,
  SensorManifestDocument,
  SensorManifestVersion,
  SensorToolContract,
} from '@/lib/api/sensor-types'

import { shortDigest } from './content'
import { formatBytes } from './format'

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

const plain: Translate = (_key, fallback = '', vars) =>
  fallback.replace(/\{(\w+)\}/g, (_, k: string) => String(vars?.[k] ?? ''))

function listDiff(prev: string[] = [], next: string[] = []) {
  return {
    added: next.filter((c) => !prev.includes(c)),
    removed: prev.filter((c) => !next.includes(c)),
  }
}

/** What changed from prev to next (the API's DiffManifests). */
export function diffManifests(
  prev: SensorManifestDocument,
  next: SensorManifestDocument
): SensorManifestDiff {
  const d: SensorManifestDiff = {}
  const before = new Map(prev.tools.map((t) => [t.name, t]))
  const after = new Set(next.tools.map((t) => t.name))
  for (const t of next.tools) {
    const p = before.get(t.name)
    if (!p) {
      ;(d.tools_added ??= []).push(t.name)
      continue
    }
    if ((p.version ?? '') !== (t.version ?? '')) {
      ;(d.versions ??= []).push({ tool: t.name, from: p.version ?? '', to: t.version ?? '' })
    }
    const pc = p.contract?.digest ?? ''
    const tc = t.contract?.digest ?? ''
    if (pc !== tc) (d.contracts ??= []).push({ tool: t.name, from: pc, to: tc })
    if (p.installed !== t.installed) {
      ;(d.installed ??= []).push({
        tool: t.name,
        from: p.installed ? 'installed' : 'not installed',
        to: t.installed ? 'installed' : 'not installed',
      })
    }
    const caps = listDiff(p.capabilities ?? [], t.capabilities ?? [])
    if (caps.added.length || caps.removed.length) {
      ;(d.capabilities ??= []).push({ tool: t.name, ...caps })
    }
  }
  for (const t of prev.tools) if (!after.has(t.name)) (d.tools_removed ??= []).push(t.name)
  const wide = listDiff(prev.capabilities ?? [], next.capabilities ?? [])
  if (wide.added.length || wide.removed.length) d.sensor_wide = wide
  const other: [string, unknown, unknown][] = [
    ['build', prev.sensor, next.sensor],
    ['sdk', prev.sdk, next.sdk],
    ['platform', prev.platform, next.platform],
    ['resources', prev.resources, next.resources],
    ['concurrency', prev.concurrency, next.concurrency],
  ]
  for (const [name, a, b] of other) {
    if (JSON.stringify(a ?? null) !== JSON.stringify(b ?? null)) (d.other ??= []).push(name)
  }
  return d
}

/** Whether a diff has anything to show. */
export function isEmptyDiff(d: SensorManifestDiff | null | undefined): boolean {
  if (!d) return true
  return (
    !d.tools_added?.length &&
    !d.tools_removed?.length &&
    !d.versions?.length &&
    !d.installed?.length &&
    !d.contracts?.length &&
    !d.capabilities?.length &&
    !d.sensor_wide &&
    !d.other?.length
  )
}

/** One line per change, for the history and the activity timeline. */
export function manifestDiffLines(d: SensorManifestDiff, t: Translate = plain): string[] {
  const lines: string[] = []
  const caps = (added?: string[], removed?: string[]) =>
    [...(added ?? []).map((c) => `+${c}`), ...(removed ?? []).map((c) => `−${c}`)].join(' ')
  if (d.tools_added?.length) {
    lines.push(
      t('sensors.manifest.toolsAdded', 'Added: {list}', { list: d.tools_added.join(', ') })
    )
  }
  if (d.tools_removed?.length) {
    lines.push(
      t('sensors.manifest.toolsRemoved', 'Removed: {list}', { list: d.tools_removed.join(', ') })
    )
  }
  for (const v of d.versions ?? []) {
    lines.push(`${v.tool} ${v.from || '—'} → ${v.to || '—'}`)
  }
  for (const i of d.installed ?? []) {
    lines.push(`${i.tool}: ${i.to}`)
  }
  for (const c of d.contracts ?? []) {
    lines.push(
      t('sensors.manifest.toolContract', '{tool} tool contract {from} → {to}', {
        tool: c.tool,
        from: shortDigest(c.from) ?? '—',
        to: shortDigest(c.to) ?? '—',
      })
    )
  }
  for (const c of d.capabilities ?? []) {
    lines.push(
      t('sensors.manifest.toolCapabilities', '{tool} capabilities: {changes}', {
        tool: c.tool ?? '',
        changes: caps(c.added, c.removed),
      })
    )
  }
  if (d.sensor_wide) {
    lines.push(
      t('sensors.manifest.sensorWide', 'Sensor-wide capabilities: {changes}', {
        changes: caps(d.sensor_wide.added, d.sensor_wide.removed),
      })
    )
  }
  if (d.other?.length) {
    lines.push(t('sensors.manifest.otherChanged', 'Changed: {list}', { list: d.other.join(', ') }))
  }
  return lines
}

/** Each version with the diff against the one before it (older); the oldest has none. */
export function manifestHistory(
  versions: SensorManifestVersion[]
): { version: SensorManifestVersion; diff: SensorManifestDiff | null }[] {
  return versions.map((v, i) => {
    const older = versions[i + 1]
    return { version: v, diff: older ? diffManifests(older.manifest, v.manifest) : null }
  })
}

/** "4 CPU cores · 23.5 GB memory", or null when none is known. */
export function resourcesText(m: SensorManifestDocument, t: Translate = plain): string | null {
  const r = m.resources
  const parts: string[] = []
  if (r?.cpu_cores) {
    const cores = Number.isInteger(r.cpu_cores) ? String(r.cpu_cores) : r.cpu_cores.toFixed(1)
    parts.push(
      r.cpu_cores === 1
        ? t('sensors.manifest.cpuCore', '{cores} CPU core', { cores })
        : t('sensors.manifest.cpuCores', '{cores} CPU cores', { cores })
    )
  }
  if (r?.mem_total_bytes) {
    parts.push(
      t('sensors.manifest.memory', '{size} memory', { size: formatBytes(r.mem_total_bytes) })
    )
  }
  return parts.length ? parts.join(', ') : null
}

/** "operator cap 8 · slots sized from CPU and memory". */
export function concurrencyText(m: SensorManifestDocument, t: Translate = plain): string | null {
  const c = m.concurrency
  if (!c) return null
  const cap =
    c.ceiling > 0
      ? t('sensors.manifest.operatorCap', 'operator cap {n}', { n: c.ceiling })
      : t('sensors.manifest.noOperatorCap', 'no operator cap')
  if (c.model === 'dynamic')
    return `${cap}, ${t('sensors.manifest.slotsDynamic', 'slots sized from CPU and memory')}`
  if (c.model === 'fixed') return `${cap}, ${t('sensors.manifest.slotsFixed', 'fixed slots')}`
  return cap
}

/** English fallbacks of the manifest sources (keys sensors.manifest.source.<source>). */
export const MANIFEST_SOURCE_LABEL: Record<string, string> = {
  sensor: 'registered by the sensor',
  heartbeat: 'derived from its heartbeat',
}

/** English fallbacks of the ignored reasons (keys sensors.manifest.ignored.<reason>). */
export const IGNORED_REASON_LABEL: Record<string, string> = {
  'unknown-member': 'not part of the manifest format',
  'unknown-tool': 'not in the tool catalog',
  'invalid-name': 'not a valid name',
  'unknown-capability': 'not a known capability',
  'invalid-contract': 'not a valid tool contract',
  limit: 'over the limit',
}

/** How the platform got a manifest version, translated (the raw value when unknown). */
export function manifestSourceLabel(source: string, t: Translate = plain): string {
  const fallback = MANIFEST_SOURCE_LABEL[source]
  return fallback ? t(`sensors.manifest.source.${source}`, fallback) : source
}

/** Why the platform ignored a manifest item, translated (the raw value when unknown). */
export function ignoredReasonLabel(reason: string, t: Translate = plain): string {
  const fallback = IGNORED_REASON_LABEL[reason]
  return fallback ? t(`sensors.manifest.ignored.${reason}`, fallback) : reason
}

/** "target-scan · T1 · network: targets" for a tool contract. */
export function contractSummary(c: SensorToolContract, t: Translate = plain): string {
  return [
    c.class,
    c.tier,
    c.network ? t('sensors.manifest.network', 'network: {network}', { network: c.network }) : null,
  ]
    .filter(Boolean)
    .join(', ')
}
