/**
 * The browser downloads only the active locale's message catalog
 * (src/lib/i18n.ts). Every catalog is about 400 KB gzipped, and importing
 * them statically put all of them in every page's first-load JS.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it, vi } from 'vitest'

const ROOTS = [join(process.cwd(), 'src'), join(process.cwd(), 'console', 'src')]

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) {
      if (name === '__tests__' || name === 'node_modules' || name === 'generated') continue
      sourceFiles(path, out)
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name)) {
      out.push(path)
    }
  }
  return out
}

// A static import of the catalogs index, a locale module or a namespace file.
const CATALOG_IMPORT =
  /^import\s+(?!type\s)[^;]*?from\s+['"][^'"]*i18n\/dictionaries(\/(en|vi)(\.ts|\/[^'"]+)?)?['"]/m

describe('message catalogs load per locale', () => {
  it('no application module imports a catalog statically', () => {
    const allowed = new Set(['src/test/setup.ts'])
    const offending = ROOTS.flatMap((root) => sourceFiles(root))
      .map((file) => relative(process.cwd(), file))
      .filter((file) => !allowed.has(file) && !file.startsWith('src/lib/i18n/dictionaries/'))
      .filter((file) => CATALOG_IMPORT.test(readFileSync(file, 'utf8')))
    expect(offending, 'use useTranslation() or getDictionary() from @/lib/i18n').toEqual([])
  })

  it('the import pattern sees a static catalog import', () => {
    expect(CATALOG_IMPORT.test("import { en } from '@/lib/i18n/dictionaries'")).toBe(true)
    expect(CATALOG_IMPORT.test("import x from './i18n/dictionaries/vi/scans.json'")).toBe(true)
    expect(CATALOG_IMPORT.test("import type { Dictionary } from '@/lib/i18n/dictionaries'")).toBe(
      false
    )
  })

  it('loads one catalog on demand, once, and falls back while nothing is loaded', async () => {
    vi.resetModules()
    const i18n = await import('@/lib/i18n')

    expect(i18n.catalogLocale('vi-VN')).toBe('vi')
    expect(i18n.catalogLocale('fr')).toBe('en')
    expect(i18n.catalogLocale(undefined)).toBe('en')

    // Nothing loaded yet: keys resolve to their fallback text.
    expect(i18n.loadedDictionary('vi')).toBeNull()
    expect(i18n.translate(i18n.getDictionary('vi'), 'common.save', 'Save')).toBe('Save')

    const first = i18n.loadDictionary('vi')
    expect(i18n.loadDictionary('vi-VN')).toBe(first)
    const dict = await first
    expect(i18n.loadedDictionary('vi')).toBe(dict)
    expect(i18n.getDictionary('vi')).toBe(dict)
    // English was never requested, so it stays out of memory; helpers that
    // ask for it get the catalog the page loaded.
    expect(i18n.loadedDictionary('en')).toBeNull()
    expect(i18n.getDictionary('en')).toBe(dict)
    expect(Object.keys(dict).length).toBeGreaterThan(1000)
  })
})
