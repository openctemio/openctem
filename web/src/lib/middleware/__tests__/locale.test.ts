/**
 * @vitest-environment node
 */
import { describe, it, expect } from 'vitest'

import { localeFromAcceptLanguage, negotiateLocale } from '../i18n'
import { getDirFromLocale, supportedLocales } from '@/lib/i18n'

describe('negotiateLocale', () => {
  it("the user's explicit choice (cookie) wins over the browser", () => {
    expect(negotiateLocale('vi', 'en-US,en;q=0.9')).toBe('vi')
    expect(negotiateLocale('en', 'vi-VN,vi;q=0.9')).toBe('en')
  })

  it('the browser language is the default when there is no choice', () => {
    expect(negotiateLocale(undefined, 'vi-VN,vi;q=0.9,en;q=0.8')).toBe('vi')
    expect(negotiateLocale(undefined, 'en-GB')).toBe('en')
  })

  it('an unknown cookie value falls back to the browser, then English', () => {
    expect(negotiateLocale('xx', 'vi')).toBe('vi')
    expect(negotiateLocale('<script>', undefined)).toBe('en')
    expect(negotiateLocale(undefined, null)).toBe('en')
  })

  it('never picks an RTL locale: none ships yet', () => {
    expect(negotiateLocale('ar', 'ar-SA,ar;q=0.9')).toBe('en')
    expect(negotiateLocale(undefined, 'he-IL,fa;q=0.9,ur;q=0.8')).toBe('en')
    for (const l of supportedLocales) expect(getDirFromLocale(l)).toBe('ltr')
  })
})

describe('localeFromAcceptLanguage', () => {
  it('honours q-values, not just the first entry', () => {
    expect(localeFromAcceptLanguage('fr-FR,fr;q=0.9,vi;q=0.8,en;q=0.7')).toBe('vi')
    expect(localeFromAcceptLanguage('en;q=0.5,vi;q=0.9')).toBe('vi')
  })

  it('keeps header order on equal q', () => {
    expect(localeFromAcceptLanguage('vi,en')).toBe('vi')
    expect(localeFromAcceptLanguage('en,vi')).toBe('en')
  })

  it('ignores q=0 (explicitly not wanted) and malformed parts', () => {
    expect(localeFromAcceptLanguage('vi;q=0,en;q=0.1')).toBe('en')
    expect(localeFromAcceptLanguage('vi;q=abc,en;q=0.1')).toBe('en')
    expect(localeFromAcceptLanguage(',,;')).toBeUndefined()
  })

  it('ignores an oversized header', () => {
    expect(localeFromAcceptLanguage(`vi,${'x'.repeat(600)}`)).toBeUndefined()
  })
})
