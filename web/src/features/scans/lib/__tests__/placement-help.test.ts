import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

import { getDictionary } from '@/lib/i18n'

import {
  FAILURE_FIX,
  GAP_CAUSES,
  GAP_CERTS,
  PLACEMENT_FIX,
  failureHelp,
  gapLabel,
  gapReasonHelp,
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

describe('host pressure placement help', () => {
  it('explains sensor_overloaded in both languages', () => {
    const h = placementHelp('sensor_overloaded')
    expect(h.text).toContain("sensor's host is overloaded")
    expect(h.href).toBe('/sensors')
    const viT = (k: string) => (vi as Record<string, string>)[k] ?? k
    expect(placementHelp('sensor_overloaded', viT).text).toContain('quá tải')
  })
})

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

function goConsts(file: string, prefix: string): string[] {
  const src = readFileSync(resolve(api, file), 'utf8')
  const re = new RegExp(`^\\s*${prefix}\\w*\\s+(?:\\w+\\s+)?=\\s*"([a-z_]+)"`, 'gm')
  return [...src.matchAll(re)].map((m) => m[1])
}

describe('every outcome reason the API keeps has words', () => {
  it('coverage-gap reasons (label and why)', () => {
    const reasons = goConsts('pkg/domain/scanrun/coverage_gaps.go', 'GapReason')
    expect(reasons).toEqual(
      expect.arrayContaining(['breaker_open', 'rate_floor', 'blocked', 'proxy_unavailable'])
    )
    for (const r of [...reasons, 'other']) {
      for (const d of [en, vi]) {
        expect(hasKey(d, `scans.tasks.gap.${r}`), `gap.${r}`).toBe(true)
        expect(hasKey(d, `scans.tasks.gapHelp.${r}`), `gapHelp.${r}`).toBe(true)
      }
    }
  })
  it('coverage-gap causes and certificate problems match the API', () => {
    const causes = goConsts('pkg/domain/scanrun/coverage_gaps.go', 'GapCause')
    const certs = goConsts('pkg/domain/scanrun/coverage_gaps.go', 'GapCert')
    expect(causes).toEqual([...GAP_CAUSES])
    expect(certs).toEqual([...GAP_CERTS])
    for (const d of [en, vi]) {
      for (const c of causes) {
        expect(hasKey(d, `scans.tasks.gapCause.${c}`), `gapCause.${c}`).toBe(true)
        expect(hasKey(d, `scans.tasks.gapCauseHelp.${c}`), `gapCauseHelp.${c}`).toBe(true)
      }
      for (const c of certs) {
        expect(hasKey(d, `scans.tasks.gapCert.${c}`), `gapCert.${c}`).toBe(true)
      }
      for (const k of [
        'scans.tasks.gapFix.addressBlock',
        'scans.tasks.gapFix.retry',
        'scans.fixLink.scannerAddresses',
      ]) {
        expect(hasKey(d, k), k).toBe(true)
      }
    }
  })
  it('skipped-target reasons', () => {
    const reasons = goConsts('pkg/domain/scanrun/skipped_targets.go', 'SkipReason')
    expect(reasons.length).toBeGreaterThanOrEqual(5)
    for (const r of reasons) {
      expect(hasKey(en, `scans.tasks.skip.${r}`), `en skip.${r}`).toBe(true)
      expect(hasKey(vi, `scans.tasks.skip.${r}`), `vi skip.${r}`).toBe(true)
    }
  })
  it('unreached reach classes', () => {
    const src = readFileSync(resolve(api, 'pkg/domain/scanrun/reach.go'), 'utf8')
    const fn = src.slice(src.indexOf('func unreachedClass'))
    const names = [...fn.slice(0, fn.indexOf('\n}\n')).matchAll(/Reach\w+/g)].map((m) => m[0])
    const values = new Map(
      [...src.matchAll(/^\s*(Reach\w+)\s*=\s*"([a-z_]+)"/gm)].map((m) => [m[1], m[2]])
    )
    expect(names.length).toBeGreaterThanOrEqual(4)
    for (const n of names) {
      const c = values.get(n)
      expect(c, n).toBeTruthy()
      expect(hasKey(en, `scans.reach.${c}`), `en reach.${c}`).toBe(true)
      expect(hasKey(vi, `scans.reach.${c}`), `vi reach.${c}`).toBe(true)
    }
  })
  it('failure classes', () => {
    const classes = goConsts('pkg/domain/scanrun/failure.go', 'FailureClass')
    expect(classes).toContain('partial')
    for (const c of classes) {
      expect(hasKey(en, `scans.failureClass.${c}`), `en failureClass.${c}`).toBe(true)
      expect(hasKey(vi, `scans.failureClass.${c}`), `vi failureClass.${c}`).toBe(true)
    }
  })
  it('COVERAGE_GAPS is a described step code', () => {
    expect(failureCodes()).toContain('COVERAGE_GAPS')
    expect(failureHelp('COVERAGE_GAPS', 'partial').text).not.toContain('does not describe')
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

describe('egress holds', () => {
  it('have text and a fix in en and vi', () => {
    for (const code of [
      'egress_unsupported',
      'egress_validate_unsupported',
      'egress_host_direct',
    ]) {
      expect(PLACEMENT_FIX[code]).toBe('sensors')
      for (const d of [en, vi]) {
        expect(hasKey(d, `scans.placement.${code}.text`), code).toBe(true)
        expect(hasKey(d, `scans.placement.${code}.fix`), code).toBe(true)
      }
      expect(placementHelp(code).href).toBe('/sensors')
    }
  })
})

describe('gapReasonHelp', () => {
  it('a host that completes the handshake and resets every request is not "stopped answering"', () => {
    const h = gapReasonHelp('breaker_open', undefined, 'http_reset', 'expired')
    expect(h.label).toMatch(/resets every HTTP request/)
    expect(h.label).not.toMatch(/stopped answering/)
    expect(h.cert).toMatch(/expired/)
    expect(h.fix).toMatch(/scanner addresses/)
    expect(h.href).toBe('/settings/scanning/proxies#scanner-addresses')
  })
  it('a host that does not answer gets the retry hint, no address link', () => {
    const h = gapReasonHelp('breaker_open', undefined, 'no_answer')
    expect(h.label).toMatch(/no answer/i)
    expect(h.href).toBeUndefined()
    expect(h.fix).toMatch(/next scan/)
  })
  it('without a recheck (an older sensor) the reason stays, worded without a guess', () => {
    const h = gapReasonHelp('breaker_open')
    expect(h.label).toBe('failed every request')
    expect(h.cert).toBeUndefined()
  })
  it('unknown cause or certificate values are ignored', () => {
    const h = gapReasonHelp('blocked', undefined, 'bogus', 'bogus')
    expect(h.label).toBe('blocked the scan')
    expect(h.cert).toBeUndefined()
    expect(h.fix).toBeUndefined()
  })
  it('gapLabel prefers the cause', () => {
    expect(gapLabel({ reason: 'breaker_open', cause: 'tls_failed' })).toMatch(
      /TLS handshake failed/
    )
    expect(gapLabel({ reason: 'rate_floor' })).toBe('kept rate-limiting the scan')
  })
})
