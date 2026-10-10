import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { en, vi, enNamespaces, viNamespaces, type Dictionary } from '.'

const dir = __dirname
const locales: Record<string, Record<string, Dictionary>> = { en: enNamespaces, vi: viNamespaces }

const filesOf = (locale: string) =>
  readdirSync(join(dir, locale))
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.slice(0, -'.json'.length))
    .sort()

describe('i18n namespace files', () => {
  for (const [locale, namespaces] of Object.entries(locales)) {
    it(`${locale}: every namespace file is imported by the index`, () => {
      expect(Object.keys(namespaces).sort()).toEqual(filesOf(locale))
    })

    it(`${locale}: every key lives in the file of its namespace, once`, () => {
      const seen = new Map<string, string>()
      for (const ns of filesOf(locale)) {
        const raw = JSON.parse(readFileSync(join(dir, locale, `${ns}.json`), 'utf8')) as Dictionary
        for (const key of Object.keys(raw)) {
          expect(key.split('.')[0], `${locale}/${ns}.json: ${key}`).toBe(ns)
          expect(seen.get(key), `${key} is in ${seen.get(key)} and ${ns}`).toBeUndefined()
          seen.set(key, ns)
        }
      }
    })
  }

  it('en and vi have the same namespaces and the same keys in each', () => {
    expect(filesOf('vi')).toEqual(filesOf('en'))
    for (const ns of filesOf('en')) {
      expect(Object.keys(viNamespaces[ns]).sort(), ns).toEqual(Object.keys(enNamespaces[ns]).sort())
    }
    expect(Object.keys(vi).sort()).toEqual(Object.keys(en).sort())
  })

  it('the merged catalog holds every key of every namespace file', () => {
    for (const [locale, namespaces] of Object.entries(locales)) {
      const merged = locale === 'en' ? en : vi
      const total = Object.values(namespaces).reduce((n, d) => n + Object.keys(d).length, 0)
      expect(Object.keys(merged)).toHaveLength(total)
      for (const d of Object.values(namespaces)) {
        for (const [k, v] of Object.entries(d)) expect(merged[k]).toBe(v)
      }
    }
  })
})
