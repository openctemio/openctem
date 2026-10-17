import { describe, expect, it } from 'vitest'
import en from '@/lib/i18n/dictionaries/en/findings.json'
import vi from '@/lib/i18n/dictionaries/vi/findings.json'
import { ALL_CLOSURE_REASONS, ALL_VERIFICATIONS, PERSON_CLOSURE_REASONS } from '../closure'

describe('closure reasons', () => {
  it('every reason and verification has an English and a Vietnamese label', () => {
    const dicts = [en as Record<string, string>, vi as Record<string, string>]
    for (const d of dicts) {
      for (const r of ALL_CLOSURE_REASONS) expect(d[`findings.closureReason.${r}`]).toBeTruthy()
      for (const v of ALL_VERIFICATIONS) expect(d[`findings.verification.${v}`]).toBeTruthy()
    }
  })

  it('a person never picks an obsolete or unknown reason', () => {
    const offered = Object.values(PERSON_CLOSURE_REASONS).flat()
    for (const r of offered) {
      expect(r.startsWith('obsolete_')).toBe(false)
      expect(r).not.toBe('unknown')
    }
  })
})
