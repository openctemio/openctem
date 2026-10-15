import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

import en from '@/lib/i18n/dictionaries/en/scans.json'
import vi from '@/lib/i18n/dictionaries/vi/scans.json'
import { REASON_LABEL, REFUSAL_CODES } from '../lib/ci'
import { CAPABILITIES, COVERAGE_STATE_META, SOURCE_KIND_LABEL } from '../lib/coverage'
import {
  FRESHNESS_LABEL,
  GATE_LABEL,
  HEALTH_REASON_LABEL,
  PIPELINE_STATUSES,
  cadenceLabel,
} from '../lib/pipeline'

/**
 * Every literal `scans.ci.*` key the CI/CD components ask for exists in both
 * the English and the Vietnamese catalog (template keys such as
 * `scans.ci.gate.${g}` are checked through their label maps' tests).
 */
describe('CI/CD i18n keys', () => {
  const dir = join(__dirname, '..', 'components')
  const keys = new Set<string>()
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.tsx'))) {
    const src = readFileSync(join(dir, f), 'utf8')
    for (const m of src.matchAll(/t\(\s*'(scans\.ci\.[A-Za-z0-9_.]+)'/g)) keys.add(m[1])
  }

  it('finds the keys it checks', () => {
    expect(keys.size).toBeGreaterThan(50)
  })

  it.each([...keys])('%s is in en and vi', (key) => {
    expect((en as Record<string, string>)[key], `en ${key}`).toBeTruthy()
    expect((vi as Record<string, string>)[key], `vi ${key}`).toBeTruthy()
  })

  it('has both catalogs for each key built from a value', () => {
    const built = [
      ...Object.keys(GATE_LABEL).map((k) => `scans.ci.gate.${k}`),
      ...Object.keys(REASON_LABEL).map((k) => `scans.ci.reason.${k}`),
      ...REFUSAL_CODES.flatMap((c) => [`scans.ci.refusal.${c}`, `scans.ci.refusal.${c}Fix`]),
      ...['provider', 'organization', 'snippet', 'waiting'].map((s) => `scans.ci.setup.step.${s}`),
      ...Object.keys(HEALTH_REASON_LABEL).map((k) => `scans.ci.health.${k}`),
      ...PIPELINE_STATUSES.flatMap((s) => [
        `scans.ci.status.${s}.label`,
        `scans.ci.status.${s}.description`,
      ]),
      ...Object.keys(FRESHNESS_LABEL).map((k) => `scans.ci.status.${k}.label`),
      ...Object.keys(COVERAGE_STATE_META).flatMap((s) => [
        `scans.ci.coverage.state.${s}.label`,
        `scans.ci.coverage.state.${s}.description`,
      ]),
      ...CAPABILITIES.map((c) => `scans.ci.coverage.capability.${c}`),
      ...Object.keys(SOURCE_KIND_LABEL).map((k) => `scans.ci.coverage.source.${k}`),
      ...['overview', 'runs', 'branches'].map((k) => `scans.ci.sheet.tab.${k}`),
    ]
    for (const key of built) {
      expect((en as Record<string, string>)[key], `en ${key}`).toBeTruthy()
      expect((vi as Record<string, string>)[key], `vi ${key}`).toBeTruthy()
    }
  })

  it('translates the cadence when given the console translator', () => {
    const t = (key: string, fallback: string, vars?: Record<string, string | number>) =>
      `${key}|${fallback}|${vars?.n ?? ''}`
    expect(cadenceLabel(6 * 3600, t)).toBe('scans.ci.cadence.hours|every {n} hours|6')
    expect(cadenceLabel(2 * 86400)).toBe('every 2 days')
  })
})
