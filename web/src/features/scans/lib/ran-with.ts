/**
 * What a step ran with (RunMapNode.ran_with): the severities and tags its
 * command carried, each with the layer that set it, so a run with no
 * findings can say what it looked for. The values are the platform's record
 * at dispatch; the ignored keys are what the sensor reported (shown as text).
 */
import { SEVERITY_LEVELS } from '@/lib/severity'

import type { Translate } from './translate'

export interface RanWithParam {
  value?: unknown
  source?: string
}

export interface RanWith {
  depth?: string
  severity?: RanWithParam
  tags?: RanWithParam
  exclude_tags?: RanWithParam
  sensor_ignored_keys?: string[]
}

// Lowest to highest (SEVERITY_LEVELS is highest first).
const SEVERITY_ORDER: string[] = [...SEVERITY_LEVELS].reverse()
const SOURCES = new Set([
  'capability_default',
  'template_step',
  'depth_overlay',
  'scan_override',
  'stage_fixed',
  'default_port_set',
])

function strings(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string')
  if (typeof v === 'string' && v) return [v]
  return []
}

/** "low..critical" for a contiguous severity run of two or more, else the list. */
export function severityText(value: unknown): string {
  const list = strings(value).map((s) => s.toLowerCase())
  const idx = list.map((s) => SEVERITY_ORDER.indexOf(s))
  if (list.length >= 2 && idx.every((i) => i >= 0)) {
    const sorted = [...idx].sort((a, b) => a - b)
    if (sorted.every((v, i) => i === 0 || v === sorted[i - 1] + 1)) {
      return `${SEVERITY_ORDER[sorted[0]]}..${SEVERITY_ORDER[sorted[sorted.length - 1]]}`
    }
  }
  return list.join(', ')
}

function sourceLabel(source: string | undefined, t: Translate): string {
  return source && SOURCES.has(source) ? t(`scans.ranWith.source.${source}`) : ''
}

function line(label: string, text: string, source: string | undefined, t: Translate): string {
  const src = sourceLabel(source, t)
  return src ? `${label} ${text} (${src})` : `${label} ${text}`
}

/** The severity line alone ("Ran with: severity low..critical (depth default)"). */
export function ranWithSeverityLine(r: RanWith | undefined, t: Translate): string | null {
  const text = severityText(r?.severity?.value)
  if (!text) return null
  return line(t('scans.ranWith.severity'), text, r?.severity?.source, t)
}

/** Every line of the step panel: severity, tags, excluded tags. */
export function ranWithLines(r: RanWith | undefined, t: Translate): string[] {
  const out: string[] = []
  const sev = ranWithSeverityLine(r, t)
  if (sev) out.push(sev)
  const tags = strings(r?.tags?.value)
  if (tags.length) out.push(line(t('scans.ranWith.tags'), tags.join(', '), r?.tags?.source, t))
  const ex = strings(r?.exclude_tags?.value)
  if (ex.length)
    out.push(line(t('scans.ranWith.excludeTags'), ex.join(', '), r?.exclude_tags?.source, t))
  return out
}
