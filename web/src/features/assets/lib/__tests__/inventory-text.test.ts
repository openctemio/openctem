import { describe, expect, it } from 'vitest'
import type { ParseResult } from '@/features/query/api/query-api'
import { applyTextResult, filtersFromParams, textParams } from '../inventory-text'
import { parseInventoryFilters } from '../inventory-url'

const q = (s: string) => new URLSearchParams(s)

function result(over: Partial<ParseResult>): ParseResult {
  return {
    entity: 'assets',
    valid: true,
    text: '',
    query: '',
    chips: [],
    advanced: false,
    problems: [],
    ...over,
  }
}

describe('the inventory filter as text and back', () => {
  it('prints the viewer filter in the API names, without the lens, tab, paging or default attribution', () => {
    const f = parseInventoryFilters(
      q(
        'lens=external_surface&tab=ip_address&criticalities=high&tags=a,b&tags_mode=all&min_risk_score=70&q=web&page=3&sort=-risk_score&network=198.51.100.0/24'
      )
    )
    const p = new URLSearchParams(textParams(f))
    expect(Object.fromEntries(p)).toEqual({
      criticality: 'high',
      tag_all: 'a,b',
      risk_score_gte: '70',
      q: 'web',
      network: '198.51.100.0/24',
    })
  })

  it('a filter chips can show comes back as the page filters, never as fq', () => {
    const next = applyTextResult(
      parseInventoryFilters(q('lens=external_surface&tab=ip_address&sort=-risk_score&page=2')),
      result({
        text: 'criticality:high port>=1 network=198.51.100.0/24',
        params: {
          criticality: 'high',
          port_gte: '1',
          network: '198.51.100.0/24',
          has_findings: 'true',
        },
      })
    )
    expect(next).toMatchObject({
      lens: 'external_surface',
      tab: 'ip_address',
      sort: '-risk_score',
      criticalities: ['high'],
      hasFindings: true,
      extra: { port_gte: '1', network: '198.51.100.0/24' },
    })
    expect(next.advanced).toBeUndefined()
    expect(next.page).toBeUndefined()
  })

  it('keeps a filter the page cannot hold whole as fq, with nothing partly dropped', () => {
    const base = parseInventoryFilters(q('criticalities=low&properties=os_family:linux'))
    const adv = applyTextResult(
      base,
      result({ text: 'criticality=high OR port=22', advanced: true })
    )
    expect(adv.advanced).toBe('criticality=high OR port=22')
    expect(adv.criticalities).toBeUndefined()
    // A param no page control stands for is also kept as text.
    const unknown = applyTextResult(
      base,
      result({ text: 'sync_health:ok', params: { sync_health: 'ok' } })
    )
    expect(unknown.advanced).toBe('sync_health:ok')
  })

  it('an empty text clears the filter but keeps the page state', () => {
    const next = applyTextResult(
      parseInventoryFilters(q('lens=external_surface&tab=domain&criticalities=low&per_page=50')),
      result({})
    )
    expect(next).toEqual({ lens: 'external_surface', tab: 'domain', pageSize: 50 })
  })

  it('a tab locks the type: a type in the text cannot widen it', () => {
    const next = applyTextResult(
      parseInventoryFilters(q('lens=external_surface&tab=ip_address')),
      result({ text: 'type=host port=22', params: { type: 'host', port: '22' } })
    )
    expect(next.types).toBeUndefined()
    expect(next.extra).toEqual({ port: '22' })
  })

  it('refuses what cannot be one page filter', () => {
    expect(filtersFromParams({ tag: 'a', tag_all: 'b' })).toBeNull()
    expect(filtersFromParams({ risk_score_gte: 'x' })).toBeNull()
    expect(filtersFromParams({ primary: 'false' })).toBeNull()
    expect(filtersFromParams({ technology_version: '1.0' })).toBeNull()
    expect(filtersFromParams({ criticality: '' })).toBeNull()
  })
})
