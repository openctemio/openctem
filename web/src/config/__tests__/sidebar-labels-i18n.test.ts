/**
 * Every sidebar item has its label in both catalogs. NavLabel falls back to the
 * English title when the key is missing, so a missing key never fails a page:
 * it just leaves English in the Vietnamese sidebar ("My Work", "Assets").
 */
import { describe, expect, it } from 'vitest'
import { sidebarData } from '../sidebar-data'
import { en, vi } from '@/lib/i18n/dictionaries'

const navItemKey = (title: string) => `nav.item.${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`

function itemTitles(node: unknown, out: string[] = []): string[] {
  if (Array.isArray(node)) {
    for (const n of node) itemTitles(n, out)
  } else if (node && typeof node === 'object') {
    const o = node as { title?: unknown; url?: unknown; items?: unknown }
    if (typeof o.title === 'string' && o.title && (o.url !== undefined || o.items !== undefined)) {
      if (o.url !== undefined || Array.isArray(o.items)) out.push(o.title)
    }
    if (o.items) itemTitles(o.items, out)
  }
  return out
}

describe('sidebar labels', () => {
  const groups = (sidebarData as { navGroups?: unknown }).navGroups ?? sidebarData
  const titles = [...new Set(itemTitles(groups))]

  it('finds the items', () => {
    expect(titles).toContain('My Work')
  })

  it.each(titles)('"%s" has a label in en and vi', (title) => {
    const key = navItemKey(title)
    expect(en[key], `${key} missing in en`).toBeTruthy()
    expect(vi[key], `${key} missing in vi`).toBeTruthy()
  })
})
