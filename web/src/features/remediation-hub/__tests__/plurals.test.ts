/**
 * Every plural block in the hub catalogs resolves for one and for many:
 * no "1 findings", no raw ICU text left on screen, in either language.
 */

import { describe, expect, it } from 'vitest'
import { en, vi } from '@/lib/i18n/dictionaries'
import { translate } from '@/lib/i18n'

const VARS = ['n', 'count', 'updated', 'findings', 'assets', 'risk', 'days']

describe('remediation hub plurals', () => {
  for (const [name, dict] of Object.entries({ en, vi })) {
    it(`${name}: plural blocks resolve for 1 and 5`, () => {
      for (const [key, value] of Object.entries(dict)) {
        if (!key.startsWith('remediationHub.') || !value.includes('plural,')) continue
        for (const n of [1, 5]) {
          const vars = Object.fromEntries(VARS.map((v) => [v, n]))
          const out = translate(dict, key, undefined, { ...vars, title: 'X' })
          expect(out, key).not.toMatch(/plural|[{}]/)
        }
      }
    })
  }

  it('says 1 finding and 5 findings', () => {
    expect(translate(en, 'remediationHub.suggestions.findingsCount', undefined, { n: 1 })).toBe(
      '1 finding'
    )
    expect(translate(en, 'remediationHub.suggestions.findingsCount', undefined, { n: 5 })).toBe(
      '5 findings'
    )
    expect(translate(en, 'remediationHub.suggestions.assetsCount', undefined, { n: 1 })).toBe(
      '1 asset'
    )
    expect(translate(en, 'remediationHub.risk.points', undefined, { n: 1 })).toBe('1 risk point')
    expect(translate(vi, 'remediationHub.panel.createsTasks', undefined, { n: 2 })).toBe(
      'Tạo 2 công việc, mỗi người phụ trách một công việc:'
    )
  })
})
