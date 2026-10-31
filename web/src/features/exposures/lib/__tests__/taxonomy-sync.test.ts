/**
 * The exposure taxonomy is declared once in the API (pkg/domain/exposure):
 * every display category, whether it has a producer, and every summary
 * sentence form. This reads that declaration so the web cannot drift: each
 * category is listed with the same `produced` flag, and each sentence form
 * has an en and a vi catalog entry.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { EXPOSURE_DISPLAY_CATEGORIES } from '@/lib/api/exposure-types'
import en from '@/lib/i18n/dictionaries/en/exposures.json'
import vi from '@/lib/i18n/dictionaries/vi/exposures.json'
import { exposureSummaryText, summaryKey } from '../summary'

const api = (f: string) =>
  readFileSync(resolve(__dirname, '../../../../../../api/pkg/domain/exposure', f), 'utf8')

function apiCategories(): { key: string; produced: boolean }[] {
  const src = api('display.go')
  const consts = new Map(
    [...src.matchAll(/(Category[A-Za-z]+)\s+DisplayCategory = "([a-z_]+)"/g)].map((m) => [
      m[1],
      m[2],
    ])
  )
  return [...src.matchAll(/\{(Category[A-Za-z]+), (true|false)\}/g)].map((m) => ({
    key: consts.get(m[1]) ?? m[1],
    produced: m[2] === 'true',
  }))
}

function apiSummaryKeys(): string[] {
  const types = new Map(
    [...api('value_objects.go').matchAll(/(EventType[A-Za-z]+)\s+EventType = "([a-z_]+)"/g)].map(
      (m) => [m[1], m[2]]
    )
  )
  const src = api('display.go')
  const body = src.slice(src.indexOf('switch t {'))
  const keys: string[] = []
  let current = ''
  for (const line of body.split('\n')) {
    const c = line.match(/^\s*case (EventType[A-Za-z]+):/)
    if (c) current = types.get(c[1]) ?? ''
    for (const m of line.matchAll(/mkSummary\("([a-z]*)"/g)) {
      keys.push(m[1] ? `exposures.summary.${current}.${m[1]}` : `exposures.summary.${current}`)
    }
  }
  return keys
}

describe('exposure taxonomy', () => {
  it('lists every API display category with the same producer flag', () => {
    const fromApi = apiCategories()
    expect(fromApi.length).toBeGreaterThan(10)
    expect(EXPOSURE_DISPLAY_CATEGORIES.map((c) => ({ key: c.key, produced: c.produced }))).toEqual(
      fromApi
    )
  })

  it('has en and vi labels for every category', () => {
    for (const c of EXPOSURE_DISPLAY_CATEGORIES) {
      expect((en as Record<string, string>)[`exposures.category.${c.key}`], c.key).toBeTruthy()
      expect((vi as Record<string, string>)[`exposures.category.${c.key}`], c.key).toBeTruthy()
    }
  })

  it('has en and vi sentences for every summary form', () => {
    const keys = apiSummaryKeys()
    expect(keys).toContain('exposures.summary.port_open')
    expect(keys).toContain('exposures.summary.port_open.port')
    for (const k of keys) {
      expect((en as Record<string, string>)[k], k).toBeTruthy()
      expect((vi as Record<string, string>)[k], k).toBeTruthy()
    }
  })
})

describe('summary text', () => {
  const t = (key: string, fallback: string, vars?: Record<string, string | number>) => {
    const tpl = (vi as Record<string, string>)[key] ?? fallback
    return tpl.replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? `{${k}}`))
  }

  it('renders the API values in the viewer language', () => {
    const e = {
      event_type: 'port_open' as const,
      summary: {
        text: 'Port 6379 (Redis) is open to the internet',
        args: { port: '6379', service: 'Redis' },
      },
    }
    expect(summaryKey(e)).toBe('exposures.summary.port_open')
    expect(exposureSummaryText(e, t)).toBe('Cổng 6379 (Redis) đang mở ra internet')
  })

  it('uses the variant key and keeps markup as text', () => {
    const e = {
      event_type: 'subdomain_takeover' as const,
      summary: { text: 'x', variant: 'domain', args: { domain: '<img src=x>.example.com' } },
    }
    expect(exposureSummaryText(e, t)).toBe('<img src=x>.example.com có thể bị chiếm')
  })

  it('shows nothing for a title fallback or no summary', () => {
    expect(
      exposureSummaryText({ event_type: 'custom', summary: { text: 'T', variant: 'title' } }, t)
    ).toBe('')
    expect(exposureSummaryText({ event_type: 'custom' }, t)).toBe('')
  })
})
