import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import en from '@/lib/i18n/dictionaries/en/ticketingIntegration.json'
import vi from '@/lib/i18n/dictionaries/vi/ticketingIntegration.json'

const source = readFileSync(join(__dirname, '..', 'page.tsx'), 'utf8')
const used = new Set(
  [...source.matchAll(/['`](ticketingIntegration\.[A-Za-z0-9_.${}]+)['`]/g)].map((m) => m[1])
)
const keys = (used.size ? [...used] : []).filter((k) => !k.includes('${'))

describe('ticketing page i18n', () => {
  it('uses ticketingIntegration keys', () => {
    expect(keys.length).toBeGreaterThan(40)
  })

  it('every key used by the page resolves in en and vi', () => {
    for (const k of keys) {
      expect((en as Record<string, string>)[k], `en ${k}`).toBeTruthy()
      expect((vi as Record<string, string>)[k], `vi ${k}`).toBeTruthy()
    }
  })

  it('resolves the dynamic finding-status keys in en and vi', () => {
    for (const st of ['confirmed', 'in_progress', 'fix_applied', 'resolved']) {
      const k = `ticketingIntegration.findingStatus.${st}`
      expect((en as Record<string, string>)[k]).toBeTruthy()
      expect((vi as Record<string, string>)[k]).toBeTruthy()
    }
  })

  it('en and vi define the same keys, with Vietnamese actually translated', () => {
    expect(Object.keys(vi).sort()).toEqual(Object.keys(en).sort())
    expect((vi as Record<string, string>)['ticketingIntegration.actions.delete']).toBe('Xóa')
  })
})
