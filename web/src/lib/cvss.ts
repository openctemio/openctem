/**
 * CVSS base vectors, version 3.1 and 4.0: metric definitions, parsing,
 * building and scoring. Scores come from ae-cvss-calculator, which follows
 * the FIRST specifications (the 4.0 macro-vector lookup included).
 */

import { Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator'

export type CvssVersion = '3.1' | '4.0'

export interface CvssMetricDef {
  key: string
  /** Value letters, in the order the calculator shows them. */
  values: string[]
  group: 'exploitability' | 'impact' | 'subsequent' | 'scope'
}

const CIA = ['H', 'L', 'N']

export const CVSS_METRICS: Record<CvssVersion, CvssMetricDef[]> = {
  '3.1': [
    { key: 'AV', values: ['N', 'A', 'L', 'P'], group: 'exploitability' },
    { key: 'AC', values: ['L', 'H'], group: 'exploitability' },
    { key: 'PR', values: ['N', 'L', 'H'], group: 'exploitability' },
    { key: 'UI', values: ['N', 'R'], group: 'exploitability' },
    { key: 'S', values: ['U', 'C'], group: 'scope' },
    { key: 'C', values: CIA, group: 'impact' },
    { key: 'I', values: CIA, group: 'impact' },
    { key: 'A', values: CIA, group: 'impact' },
  ],
  '4.0': [
    { key: 'AV', values: ['N', 'A', 'L', 'P'], group: 'exploitability' },
    { key: 'AC', values: ['L', 'H'], group: 'exploitability' },
    { key: 'AT', values: ['N', 'P'], group: 'exploitability' },
    { key: 'PR', values: ['N', 'L', 'H'], group: 'exploitability' },
    { key: 'UI', values: ['N', 'P', 'A'], group: 'exploitability' },
    { key: 'VC', values: CIA, group: 'impact' },
    { key: 'VI', values: CIA, group: 'impact' },
    { key: 'VA', values: CIA, group: 'impact' },
    { key: 'SC', values: CIA, group: 'subsequent' },
    { key: 'SI', values: CIA, group: 'subsequent' },
    { key: 'SA', values: CIA, group: 'subsequent' },
  ],
}

export type CvssMetrics = Record<string, string>

export interface ParsedCvss {
  version: CvssVersion
  metrics: CvssMetrics
  /** Every base metric has a value. */
  complete: boolean
}

const PREFIX: Record<CvssVersion, string> = { '3.1': 'CVSS:3.1/', '4.0': 'CVSS:4.0/' }

/** Version of a vector string from its prefix, or null. */
export function cvssVersionOf(vector: string): CvssVersion | null {
  const v = vector.trim().toUpperCase()
  if (v.startsWith(PREFIX['3.1'])) return '3.1'
  if (v.startsWith(PREFIX['4.0'])) return '4.0'
  return null
}

/**
 * Parses a base vector. Unknown metrics, invalid values and repeated metrics
 * make it invalid (null); metrics outside the base group (temporal, threat,
 * environmental, supplemental) are ignored. A vector may be partial.
 */
export function parseCvssVector(vector: string): ParsedCvss | null {
  const version = cvssVersionOf(vector)
  if (!version) return null
  const defs = CVSS_METRICS[version]
  const metrics: CvssMetrics = {}
  const body = vector.trim().slice(PREFIX[version].length)
  if (!body) return { version, metrics, complete: false }
  for (const part of body.split('/')) {
    const [rawKey, rawValue, extra] = part.split(':')
    if (extra !== undefined || !rawKey || !rawValue) return null
    const key = rawKey.toUpperCase()
    const value = rawValue.toUpperCase()
    const def = defs.find((d) => d.key === key)
    if (!def) {
      // A non-base metric is fine to paste; it is not scored here.
      if (/^[A-Z]{1,3}$/.test(key)) continue
      return null
    }
    if (!def.values.includes(value) || key in metrics) return null
    metrics[key] = value
  }
  return { version, metrics, complete: defs.every((d) => d.key in metrics) }
}

export function buildCvssVector(version: CvssVersion, metrics: CvssMetrics): string {
  const parts = CVSS_METRICS[version]
    .filter((d) => metrics[d.key])
    .map((d) => `${d.key}:${metrics[d.key]}`)
  return parts.length ? `${PREFIX[version]}${parts.join('/')}` : ''
}

/** Base score of a complete vector, or null. */
export function scoreCvss(version: CvssVersion, metrics: CvssMetrics): number | null {
  if (!CVSS_METRICS[version].every((d) => metrics[d.key])) return null
  const vector = buildCvssVector(version, metrics)
  try {
    const scores =
      version === '3.1'
        ? new Cvss3P1(vector).calculateScores()
        : new Cvss4P0(vector).calculateScores()
    const base = scores.base
    return typeof base === 'number' && Number.isFinite(base) ? base : null
  } catch {
    return null
  }
}
