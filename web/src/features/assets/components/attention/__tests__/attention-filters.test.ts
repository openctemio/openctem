/**
 * Every attribution and monitoring state value the web sends to GET /assets
 * is one the API's list registry accepts (server/pkg/domain/assetlist). The
 * decide-monitoring and validate-primary queues ask for every attribution
 * value the inventory offers; when the inventory gained `provider_address`
 * and the registry did not, the API answered 400 "1 filter error" and both
 * queues (and the inventory's "Show all" and provider chip) never loaded.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { buildAssetQueryParams } from '../../../hooks/use-assets'
import { ATTRIBUTION_FILTER_VALUES, DEFAULT_ATTRIBUTION } from '../../../lib/inventory-url'
import { MONITORING_STATES } from '../../../lib/monitoring-state'
import { ATTENTION_FILTERS, attentionCountQuery, type AttentionReason } from '../attention-filters'

const SERVER = resolve(__dirname, '../../../../../../../server/pkg/domain')

/** The body of a Go func, from its signature to the closing brace at column 0. */
function funcBody(src: string, name: string): string {
  const start = src.indexOf(`func ${name}(`)
  if (start < 0) throw new Error(`func ${name} not found`)
  return src.slice(start, src.indexOf('\n}\n', start))
}

/** The attribution words the asset list registry accepts. */
function apiAttributionValues(): Set<string> {
  const attr = readFileSync(resolve(SERVER, 'attribution/attribution.go'), 'utf8')
  const consts = new Map(
    [...attr.matchAll(/\b((?:Filter|State)[A-Za-z]+)\s+(?:State\s+)?=\s+"([a-z_]+)"/g)].map((m) => [
      m[1],
      m[2],
    ])
  )
  const fields = readFileSync(resolve(SERVER, 'assetlist/fields.go'), 'utf8')
  const refs = [
    funcBody(fields, 'attributionFilterNames'),
    funcBody(fields, 'storedAttributionStates'),
  ].join('\n')
  const out = new Set<string>()
  for (const m of refs.matchAll(/attribution\.((?:Filter|State)[A-Za-z]+)/g)) {
    const v = consts.get(m[1])
    if (v) out.add(v)
  }
  return out
}

const REASONS = Object.keys(ATTENTION_FILTERS) as AttentionReason[]

describe('attention queue filters', () => {
  const accepted = apiAttributionValues()

  it('reads the API set', () => {
    // A parse that finds nothing would pass every check below.
    expect(accepted.has('confirmed')).toBe(true)
    expect(accepted.has('approved')).toBe(true)
  })

  it('offers only attribution values the API accepts', () => {
    for (const v of [...ATTRIBUTION_FILTER_VALUES, ...DEFAULT_ATTRIBUTION]) {
      expect(accepted.has(v), v).toBe(true)
    }
  })

  it.each(REASONS)('%s sends a query the API accepts', (reason) => {
    const params = buildAssetQueryParams(attentionCountQuery(reason, false))
    for (const v of (params.attribution ?? '').split(',').filter(Boolean)) {
      expect(accepted.has(v), `${reason}: attribution=${v}`).toBe(true)
    }
    for (const v of (params.monitoring_state ?? '').split(',').filter(Boolean)) {
      expect((MONITORING_STATES as readonly string[]).includes(v), `${reason}: ${v}`).toBe(true)
    }
  })

  it('asks the undecided queues for every attribution, names awaiting review included', () => {
    for (const reason of ['decide_monitoring', 'validate_primary'] as const) {
      const params = buildAssetQueryParams(attentionCountQuery(reason, false))
      expect(params.monitoring_state).toBe('pending_decision,unvalidated')
      expect(params.attribution?.split(',')).toContain('needs_review')
    }
    expect(buildAssetQueryParams(attentionCountQuery('validate_primary', false)).primary).toBe(
      'true'
    )
  })
})
