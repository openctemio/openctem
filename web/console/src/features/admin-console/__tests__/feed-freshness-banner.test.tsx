import { describe, expect, it } from 'vitest'
import { freshnessLines, type AdminFreshnessCondition } from '../components/feed-freshness-banner'
import { codeProblem } from '../lib/feed-status'

/** The fallback text with its params filled in, as the English catalog renders. */
const t = (_key: string, fallback: string, params?: Record<string, string | number>) =>
  fallback.replace(/\{(\w+)\}/g, (_, k: string) => String(params?.[k] ?? `{${k}}`))

const cond = (c: Partial<AdminFreshnessCondition>): AdminFreshnessCondition => ({
  key: 'k',
  code: 'data_stale',
  banner: true,
  since: '2026-11-20T00:00:00Z',
  detail: 'English detail',
  ...c,
})

describe('freshnessLines', () => {
  it('names the feed, what is wrong and why, from the same feed’s import problem', () => {
    const lines = freshnessLines(
      [
        cond({ key: 'data_stale:kev', source: 'kev', limit_seconds: 43200 }),
        cond({
          key: 'import_failing:kev',
          code: 'import_failing',
          source: 'kev',
          banner: false,
          error_code: 'proxy_refused',
          error_params: { status: '407', host: 'github.com' },
        }),
      ],
      t
    )
    expect(lines).toHaveLength(1)
    expect(lines[0].what).toBe(
      'CISA KEV (known exploited vulnerabilities): no data has been loaded yet.'
    )
    expect(lines[0].why).toBe('The feed proxy refused the connection (407).')
    expect(lines[0].fix).toMatch(/OPENCTEM_HTTPSEC_FEED_PROXY/)
  })

  it('says how old the data is and the limit', () => {
    const asOf = new Date(Date.now() - 20 * 3600 * 1000).toISOString()
    const [line] = freshnessLines(
      [cond({ source: 'vulnfeed', as_of: asOf, limit_seconds: 43200 })],
      t,
      'en'
    )
    expect(line.what).toMatch(
      /^Vulnerability bundles: the newest data is from .+, older than the limit of 12 h\.$/
    )
    expect(line.why).toBeUndefined()
  })

  it('does not show administrator-only conditions as banner lines', () => {
    expect(freshnessLines([cond({ code: 'volume_low', banner: false })], t)).toHaveLength(0)
  })
})

describe('codeProblem', () => {
  it('tells a blocked private address apart from an unreachable host', () => {
    expect(codeProblem('blocked_address', { host: 'mirror.example.com' }, t).message).toBe(
      'mirror.example.com is on a private address that is not allowed.'
    )
    expect(codeProblem('unreachable', { host: 'github.com' }, t).message).toBe(
      'Cannot reach github.com.'
    )
  })

  it('asks for a restart when a server setting was refused at start-up', () => {
    const p = codeProblem('blocked_address', { host: '10.0.0.5', setting: 'VULNFEED_BASE_URL' }, t)
    expect(p.action).toMatch(/Fix VULNFEED_BASE_URL on the server, then restart the API\.$/)
    expect(codeProblem('config_invalid', { setting: 'VULNFEED_BASE_URL' }, t).message).toMatch(
      /VULNFEED_BASE_URL/
    )
  })

  it('names a proxy that cannot be reached and one that wants a sign-in', () => {
    expect(codeProblem('proxy_unreachable', {}, t).message).toBe(
      'The feed proxy cannot be reached.'
    )
    expect(codeProblem('proxy_refused', { status: '407' }, t).action).toMatch(/sign-in/)
    expect(codeProblem('proxy_refused', { status: '403' }, t).action).toMatch(
      /allowed on the proxy/
    )
  })
})
