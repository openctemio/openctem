import { describe, expect, it } from 'vitest'

import en from '@/lib/i18n/dictionaries/en.json'
import vi from '@/lib/i18n/dictionaries/vi.json'
import { getDictionary, translate } from '@/lib/i18n'
import {
  SCOPE_ERROR_CODES,
  SCOPE_FIX_ACTIONS,
  SCOPE_REFUSAL_CODES,
  scopeErrorMessage,
  scopeErrorText,
  scopeFixLabel,
  scopeRefusalLabel,
  scopeRefusalMessage,
} from '../scope-codes'

const tEn = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  translate(getDictionary('en'), key, fallback, vars)
const tVi = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  translate(getDictionary('vi'), key, fallback, vars)

const EN = en as Record<string, string>
const VI = vi as Record<string, string>

// Every refusal code of RFC-054 §6.5 and every error code of §6.1 / §8 has a
// sentence in both catalogs: a refusal never shows a raw code.
describe('scope code catalogs', () => {
  it.each(SCOPE_REFUSAL_CODES)('refusal %s has en and vi label and message', (code) => {
    for (const kind of ['label', 'message']) {
      const key = `scope.refusal.${kind}.${code}`
      expect(EN[key], key).toBeTruthy()
      expect(VI[key], key).toBeTruthy()
    }
  })

  it.each(SCOPE_ERROR_CODES)('error %s has en and vi text', (code) => {
    expect(EN[`scope.error.${code}`]).toBeTruthy()
    expect(VI[`scope.error.${code}`]).toBeTruthy()
  })

  it.each(SCOPE_FIX_ACTIONS)('fix %s has en and vi text', (action) => {
    expect(EN[`scope.fix.${action}`]).toBeTruthy()
    expect(VI[`scope.fix.${action}`]).toBeTruthy()
  })

  it('covers every refusal code the API sends', () => {
    // api/pkg/domain/scope/refusal.go
    const server = [
      'invalid_target',
      'deny_list',
      'excluded',
      'rejected',
      'needs_review',
      'candidate',
      'dependency',
      'monitor_only',
      'no_entry',
      'entry_pending',
      'entry_expired',
      'entry_inactive',
      'tier_exceeds',
      'proof_required',
      'out_of_data_scope',
      'not_an_asset',
      'zone_none',
      'zone_no_sensor',
      'zone_sensor_mismatch',
      'program_platform',
      'constrained',
    ]
    expect([...SCOPE_REFUSAL_CODES].sort()).toEqual([...server].sort())
  })
})

describe('scope code text', () => {
  it('labels and explains a known refusal, in the reader language', () => {
    expect(scopeRefusalLabel(tEn, 'no_entry')).toBe('Not in scope')
    expect(scopeRefusalLabel(tVi, 'no_entry')).toBe('Ngoài phạm vi')
    expect(scopeRefusalMessage(tEn, 'excluded')).toMatch(/exclusion/)
  })

  it('uses the server message for a code it does not know, never the raw code', () => {
    expect(scopeRefusalMessage(tEn, 'brand_new_code', 'Server says no.')).toBe('Server says no.')
    expect(scopeRefusalLabel(tEn, 'brand_new_code')).toBe('Refused')
    expect(scopeRefusalMessage(tEn, '__proto__')).toBe('This target may not be scanned.')
  })

  it('maps API errors by code, then by message', () => {
    expect(scopeErrorMessage(tEn, { code: 'PUBLIC_SUFFIX', message: 'raw' }, 'x')).toMatch(
      /public suffix/i
    )
    expect(scopeErrorMessage(tVi, { code: 'ENTRY_SELF_APPROVAL' }, 'x')).toMatch(/người phê duyệt/)
    expect(scopeErrorMessage(tEn, { code: 'OTHER', message: 'Server text' }, 'x')).toBe(
      'Server text'
    )
    expect(scopeErrorMessage(tEn, null, 'Fallback')).toBe('Fallback')
    expect(scopeErrorText(tEn, 'constructor')).toBeUndefined()
  })

  it('fills fix labels from the fix', () => {
    expect(scopeFixLabel(tEn, { action: 'allow_temporarily', days: 7 })).toBe('Allow for 7 days')
    expect(scopeFixLabel(tVi, { action: 'verify_domain', domain: 'acme.io' })).toBe(
      'Xác minh acme.io'
    )
    expect(scopeFixLabel(tEn, { action: 'future_fix' })).toBe('future fix')
  })
})
