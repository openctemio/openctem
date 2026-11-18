/**
 * Guard: the breadcrumb names every page with the key its heading is rendered
 * with, so the last crumb equals the page heading (or the active tab) in
 * English and in Vietnamese, and no crumb falls back to the URL segment.
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { en } from '@/lib/i18n/dictionaries/en'
import { vi } from '@/lib/i18n/dictionaries/vi'
import * as sectionTabs from '@/config/section-tabs'
import { breadcrumbLabelKey } from '../breadcrumb-labels'
import { PATHS_WITHOUT_PAGE } from '../breadcrumb-routes'

const SHELL_DIR = join(process.cwd(), 'src', 'app', '(dashboard)')

/** Static page routes of the shell (route groups removed), with their page file. */
function shellPages(dir = SHELL_DIR, segments: string[] = [], out = new Map<string, string>()) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      if (/^\[.*\]$/.test(name)) continue // record pages are named by their record
      shellPages(full, /^\(.*\)$/.test(name) ? segments : [...segments, name], out)
    } else if (name === 'page.tsx' && segments.length > 0) {
      out.set('/' + segments.join('/'), full)
    }
  }
  return out
}

const enDict = en as Record<string, string>
const viDict = vi as Record<string, string>

/** The `t()` key of the page's own `<PageHeader title=...>`, when the page file renders one. */
function headingKey(file: string): string | undefined {
  const src = readFileSync(file, 'utf8')
  const header = src.match(/<PageHeader\b[\s\S]{0,400}?\btitle=\{t\(\s*['"]([^'"]+)['"]/)
  return header?.[1]
}

const tabKeys = new Set<string>()
for (const value of Object.values(sectionTabs)) {
  if (!Array.isArray(value)) continue
  for (const tab of value as { href?: string; labelKey?: string }[]) {
    if (tab?.href && tab.labelKey) tabKeys.add(tab.href)
  }
}

describe('breadcrumb equals the page heading', () => {
  const pages = shellPages()

  it('finds the shell pages', () => {
    expect(pages.size).toBeGreaterThan(100)
  })

  it('names every crumb of every page with a key that exists in en and vi', () => {
    const missing: string[] = []
    for (const route of pages.keys()) {
      const parts = route.split('/').filter(Boolean)
      for (let i = 1; i <= parts.length; i++) {
        const path = '/' + parts.slice(0, i).join('/')
        if (
          i < parts.length &&
          PATHS_WITHOUT_PAGE.has(path) &&
          !breadcrumbLabelKey(path, parts[i - 1])
        )
          continue
        const key = breadcrumbLabelKey(path, parts[i - 1])
        if (!key || !enDict[key] || !viDict[key]) missing.push(`${path} -> ${key ?? '(none)'}`)
      }
    }
    expect(missing).toEqual([])
  })

  it('uses the heading key of every page that renders its own PageHeader title', () => {
    const differ: string[] = []
    for (const [route, file] of pages) {
      if (tabKeys.has(route)) continue // the active tab names these pages
      const heading = headingKey(file)
      if (!heading) continue
      const segment = route.split('/').pop()!
      const crumb = breadcrumbLabelKey(route, segment)
      for (const [lang, dict] of [
        ['en', enDict],
        ['vi', viDict],
      ] as const) {
        const want = dict[heading]
        const got = crumb ? dict[crumb] : undefined
        if (want && got !== want)
          differ.push(`${lang} ${route}: crumb "${got}" vs heading "${want}"`)
      }
    }
    expect(differ).toEqual([])
  })

  it('names a tab page after its tab', () => {
    for (const value of Object.values(sectionTabs)) {
      if (!Array.isArray(value)) continue
      for (const tab of value as { href?: string; label?: string; labelKey?: string }[]) {
        if (!tab?.href || !tab.labelKey || tab.label === 'Overview') continue
        expect(breadcrumbLabelKey(tab.href, tab.href.split('/').pop()!), tab.href).toBe(
          tab.labelKey
        )
      }
    }
  })
})
