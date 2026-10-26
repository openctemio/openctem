import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'
import en from '@/lib/i18n/dictionaries/en/letters.json'
import vi from '@/lib/i18n/dictionaries/vi/letters.json'

// Every letters.* key the page asks for must exist in both languages, or
// Vietnamese users see the English fallback everywhere.
const page = readFileSync(
  path.resolve(__dirname, '../../../app/(dashboard)/(scoping)/scope/letters/page.tsx'),
  'utf8'
)
const keys = [...new Set([...page.matchAll(/t\(\s*'(letters\.[\w.]+)'/g)].map((m) => m[1]))]

describe('scope letters dictionaries', () => {
  it('finds the page keys', () => {
    expect(keys.length).toBeGreaterThanOrEqual(28)
  })

  it.each(keys)('%s has an en and a vi value', (key) => {
    const e = (en as Record<string, string>)[key]
    const v = (vi as Record<string, string>)[key]
    expect(e, `en ${key}`).toBeTruthy()
    expect(v, `vi ${key}`).toBeTruthy()
  })
})
