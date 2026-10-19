import { describe, it, expect } from 'vitest'
import { getDictionary, translate, getDirFromLocale } from '../i18n'
import { en, vi } from '../i18n/dictionaries'

describe('i18n translate', () => {
  it('resolves a key from the requested locale catalog', () => {
    const vi = getDictionary('vi')
    expect(translate(vi, 'nav.group.scoping')).toBe('Phạm vi')
    expect(translate(vi, 'common.cancel')).toBe('Hủy')
  })

  it('falls back to English when a key is missing from a non-English catalog', () => {
    const vi = getDictionary('vi')
    // A key present in en but (hypothetically) absent from vi resolves to en.
    const partial = { ...vi }
    delete (partial as Record<string, string>)['common.save']
    expect(translate(partial, 'common.save')).toBe('Save')
  })

  it('falls back to the provided fallback, then the key, when absent everywhere', () => {
    const en = getDictionary('en')
    expect(translate(en, 'does.not.exist', 'My Fallback')).toBe('My Fallback')
    expect(translate(en, 'does.not.exist')).toBe('does.not.exist')
  })

  it('interpolates {vars}', () => {
    const en = getDictionary('en')
    expect(translate(en, 'common.rowsExported', undefined, { count: 42 })).toBe('Exported 42 rows')
    const vi = getDictionary('vi')
    expect(translate(vi, 'common.rowsExported', undefined, { count: 42 })).toBe('Đã xuất 42 dòng')
  })

  it('getDictionary falls back to English for an untranslated locale (ar) and strips region', () => {
    expect(getDictionary('ar')).toEqual(getDictionary('en'))
    expect(translate(getDictionary('vi-VN'), 'nav.group.settings')).toBe('Cài đặt')
  })

  it('RTL direction still derives from locale (ar) independent of translation', () => {
    expect(getDirFromLocale('ar')).toBe('rtl')
    expect(getDirFromLocale('vi')).toBe('ltr')
  })

  // Guards catalog drift: every English key must have a Vietnamese translation
  // (and vice-versa), and no value may be left empty.
  it('en and vi catalogs have identical, non-empty keys', () => {
    const enKeys = Object.keys(en).sort()
    const viKeys = Object.keys(vi).sort()
    expect(viKeys).toEqual(enKeys)
    for (const k of enKeys) {
      expect((en as Record<string, string>)[k]).not.toBe('')
      expect((vi as Record<string, string>)[k]).not.toBe('')
    }
  })
})

describe('i18n plurals', () => {
  const dict = {
    a: '{n, plural, one {# finding} other {# findings}}',
    b: '{f, plural, =0 {No findings} one {# finding} other {# findings}} on {a, plural, one {# asset} other {# assets}}',
    c: '{n, plural, other {# mục}}',
  }
  it('picks one and other', () => {
    expect(translate(dict, 'a', undefined, { n: 1 })).toBe('1 finding')
    expect(translate(dict, 'a', undefined, { n: 5 })).toBe('5 findings')
    expect(translate(dict, 'a', undefined, { n: 0 })).toBe('0 findings')
  })
  it('handles =0 and several blocks in one string', () => {
    expect(translate(dict, 'b', undefined, { f: 1, a: 1 })).toBe('1 finding on 1 asset')
    expect(translate(dict, 'b', undefined, { f: 5, a: 2 })).toBe('5 findings on 2 assets')
    expect(translate(dict, 'b', undefined, { f: 0, a: 3 })).toBe('No findings on 3 assets')
  })
  it('a language with only other never says one', () => {
    expect(translate(dict, 'c', undefined, { n: 1 })).toBe('1 mục')
  })
  it('groups thousands and leaves a block with a missing number alone', () => {
    expect(translate(dict, 'a', undefined, { n: 1234 })).toBe('1,234 findings')
    expect(translate(dict, 'a')).toContain('plural')
  })
})
