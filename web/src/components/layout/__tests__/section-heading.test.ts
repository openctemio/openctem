/**
 * Guard: one heading per tabbed section. Every tab page of a section renders
 * the section's own title (and the tab row names the sub-page), so switching
 * tabs never changes the title and never moves the tab row. A page whose
 * heading is drawn by a shared frame (HubPage, ScansPageHeader) is checked
 * through that frame's own tests.
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import * as sectionTabs from '@/config/section-tabs'

const SHELL_DIR = join(process.cwd(), 'src', 'app', '(dashboard)')

function shellPages(dir = SHELL_DIR, segments: string[] = [], out = new Map<string, string>()) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      if (/^\[.*\]$/.test(name)) continue
      shellPages(full, /^\(.*\)$/.test(name) ? segments : [...segments, name], out)
    } else if (name === 'page.tsx' && segments.length > 0) {
      out.set('/' + segments.join('/'), full)
    }
  }
  return out
}

/** Every `t()` key a page passes as a PageHeader title (a page may render several states). */
function headingKeys(file: string): string[] {
  const src = readFileSync(file, 'utf8')
  const keys = new Set<string>()
  for (const m of src.matchAll(/<PageHeader\b[\s\S]{0,400}?\btitle=\{t\(\s*['"]([^'"]+)['"]/g))
    keys.add(m[1])
  return [...keys]
}

describe('a tabbed section keeps one heading on every tab', () => {
  const pages = shellPages()
  for (const [name, value] of Object.entries(sectionTabs)) {
    if (!name.endsWith('_SECTION_TABS') || !Array.isArray(value)) continue
    it(name, () => {
      const seen = new Map<string, string[]>()
      for (const tab of value as { href?: string }[]) {
        const file = tab?.href ? pages.get(tab.href) : undefined
        if (!file) continue
        for (const key of headingKeys(file)) seen.set(key, [...(seen.get(key) ?? []), tab.href!])
      }
      expect(Object.fromEntries(seen), `${name}: one title key`).toSatisfy(
        (o: Record<string, string[]>) => Object.keys(o).length <= 1
      )
    })
  }
})
