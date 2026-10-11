import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

import en from '@/lib/i18n/dictionaries/en/scans.json'
import vi from '@/lib/i18n/dictionaries/vi/scans.json'

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

  it('has a Vietnamese value for each template key the cells build', () => {
    for (const k of ['passing', 'failing', 'none']) {
      expect((vi as Record<string, string>)[`scans.ci.gate.${k}`]).toBeTruthy()
    }
    for (const k of ['daemon', 'runner']) {
      expect((vi as Record<string, string>)[`scans.ci.mode.${k}`]).toBeTruthy()
    }
  })
})
