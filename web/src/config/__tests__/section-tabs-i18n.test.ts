/**
 * Every section tab has a labelKey with a value in both catalogs. SectionTabs
 * falls back to the English label when the key is missing, so a tab without
 * one silently stays English in the Vietnamese console.
 */
import { describe, expect, it } from 'vitest'
import * as tabs from '../section-tabs'
import { en, vi } from '@/lib/i18n/dictionaries'

const lists = Object.entries(tabs).filter(
  ([name, v]) => name.endsWith('_SECTION_TABS') && Array.isArray(v)
) as [string, readonly { label: string; labelKey?: string }[]][]

describe('section tabs i18n', () => {
  it('finds the tab lists', () => {
    expect(lists.length).toBeGreaterThanOrEqual(8)
  })

  for (const [name, list] of lists) {
    it(`${name}: every tab has a labelKey in en and vi`, () => {
      for (const tab of list) {
        expect(tab.labelKey, `${name} tab "${tab.label}" has no labelKey`).toBeTruthy()
        const key = tab.labelKey as string
        expect((en as Record<string, string>)[key], `en ${key}`).toBe(tab.label)
        expect((vi as Record<string, string>)[key], `vi ${key}`).toBeTruthy()
      }
    })
  }

  it('the Vietnamese tab labels are not the English words', () => {
    const same = lists
      .flatMap(([, l]) => l)
      .filter((t) => t.labelKey && (vi as Record<string, string>)[t.labelKey] === t.label)
      .map((t) => t.label)
    // Words that are the same in both languages.
    expect(same.filter((s) => !['Scope'].includes(s))).toEqual([])
  })
})
