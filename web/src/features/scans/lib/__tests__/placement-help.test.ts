import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

import { getDictionary } from '@/lib/i18n'

import {
  FAILURE_FIX,
  PLACEMENT_FIX,
  failureHelp,
  placementHelp,
  placementKey,
} from '../placement-help'

// The API's code lists, read from its source: a code the API can send
// without an entry here fails this test.
const api = resolve(__dirname, '../../../../../../api')

function failureCodes(): string[] {
  const src = readFileSync(resolve(api, 'pkg/domain/scanrun/failure.go'), 'utf8')
  const block = src.slice(src.indexOf('var failureClasses'))
  const body = block.slice(0, block.indexOf('\n}'))
  const names = [...body.matchAll(/^\s*(Failure\w+):/gm)].map((m) => m[1])
  // The values may be declared in any file of the package (reach.go).
  const dir = resolve(api, 'pkg/domain/scanrun')
  const all = readdirSync(dir)
    .filter((f) => f.endsWith('.go') && !f.endsWith('_test.go'))
    .map((f) => readFileSync(resolve(dir, f), 'utf8'))
    .join('\n')
  const values = new Map(
    [...all.matchAll(/^\s*(?:const\s+)?(Failure\w+)\s*=\s*"([A-Z_]+)"/gm)].map((m) => [m[1], m[2]])
  )
  return names.map((n) => {
    const v = values.get(n)
    if (!v) throw new Error(`no value for ${n}`)
    return v
  })
}

function placementCodes(): string[] {
  const src = readFileSync(resolve(api, 'pkg/domain/command/placement.go'), 'utf8')
  return [...src.matchAll(/^\s*Placement\w+\s*=\s*"([a-z_]+)"/gm)].map((m) => m[1])
}

const en = getDictionary('en')
const vi = getDictionary('vi')
function hasKey(d: unknown, key: string): boolean {
  return typeof (d as Record<string, unknown>)[key] === 'string'
}

describe('every code the API sends has help', () => {
  it('step failure codes', () => {
    const codes = failureCodes()
    expect(codes.length).toBeGreaterThan(25)
    for (const code of codes) {
      expect(FAILURE_FIX, code).toHaveProperty(code)
      for (const part of ['text', 'fix']) {
        expect(hasKey(en, `scans.failure.${code}.${part}`), `en ${code}.${part}`).toBe(true)
        expect(hasKey(vi, `scans.failure.${code}.${part}`), `vi ${code}.${part}`).toBe(true)
      }
    }
  })

  it('placement reason codes', () => {
    const codes = placementCodes()
    expect(codes).toContain('tool_missing')
    for (const code of codes) {
      const key = placementKey(code === 'grant_' ? 'grant_tools' : code)
      expect(PLACEMENT_FIX, code).toHaveProperty(key)
      for (const part of ['text', 'fix']) {
        expect(hasKey(en, `scans.placement.${key}.${part}`), `en ${key}.${part}`).toBe(true)
        expect(hasKey(vi, `scans.placement.${key}.${part}`), `vi ${key}.${part}`).toBe(true)
      }
    }
  })
})

describe('failureHelp', () => {
  it('explains a known code with its class and a fix link', () => {
    const h = failureHelp('NO_CONFINED_SENSOR', 'placement')
    expect(h.classLabel).toBe('Placement')
    expect(h.text).toMatch(/web scope/)
    expect(h.fix).toMatch(/seccomp/)
    expect(h.href).toBe('/sensors')
  })

  it('keeps an unknown code and invents no fix', () => {
    const h = failureHelp('SOMETHING_NEW', 'nonsense')
    expect(h.text).toContain('SOMETHING_NEW')
    expect(h.fix).toBeUndefined()
    expect(h.href).toBeUndefined()
    expect(h.classLabel).toBeUndefined()
  })
})

describe('placementHelp', () => {
  it('names the grant dimension', () => {
    const h = placementHelp('grant_tier_ceiling')
    expect(h.text).toContain('tier ceiling')
    expect(h.href).toBe('/sensors')
  })

  it('a zone reason links to the zones', () => {
    expect(placementHelp('outside_zone').href).toBe('/sensors?tab=zones')
    expect(placementHelp('window_closed').href).toBe('/settings/scanning/scan-windows')
  })
})

describe('rule_sources_unsupported', () => {
  it('has a fix target and translated help in en and vi', () => {
    expect(PLACEMENT_FIX.rule_sources_unsupported).toBe('sensors')
    for (const lang of ['en', 'vi'] as const) {
      const dict = getDictionary(lang) as Record<string, string>
      expect(dict['scans.placement.rule_sources_unsupported.text']).toBeTruthy()
      expect(dict['scans.placement.rule_sources_unsupported.fix']).toBeTruthy()
    }
  })
})
