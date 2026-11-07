import { describe, expect, it } from 'vitest'
import {
  normalizeQuery,
  parseUserAgentList,
  queryError,
  requiredWithoutMarker,
  userAgentBothError,
  userAgentListErrors,
  headerListErrors,
  headerNameError,
  headerValueError,
  mergeIdentity,
  normalizeHeaders,
  previewLines,
  userAgentError,
} from '../scan-identification'

// The rules mirror the API (api pkg/domain/scanident).
describe('scan identification rules', () => {
  it('accepts any token name, refuses transport and credential names', () => {
    for (const ok of ['ATTT', 'X-Scanner', "a!#$%&'*+-.^_`|~9"])
      expect(headerNameError(ok)).toBeNull()
    for (const bad of ['', 'Has Space', 'Colon:', 'n'.repeat(65), 'Ünicode'])
      expect(headerNameError(bad)).not.toBeNull()
    for (const refused of [
      'Host',
      'content-length',
      'Transfer-Encoding',
      'Connection',
      'TE',
      'Upgrade',
      'Proxy-Authorization',
      'proxy-x',
      'Cookie',
      'AUTHORIZATION',
    ])
      expect(headerNameError(refused)).toBe(
        'Connection, proxy and credential headers cannot be set.'
      )
  })
  it('refuses line breaks and long values', () => {
    expect(headerValueError('is-here')).toBeNull()
    expect(headerValueError('a\r\nX-Injected: 1')).not.toBeNull()
    expect(headerValueError('v'.repeat(201))).not.toBeNull()
    expect(userAgentError('a\nb')).not.toBeNull()
    expect(userAgentError('a'.repeat(257))).toBe('At most 256 characters.')
  })
  it('flags case-insensitive duplicates', () => {
    expect(
      headerListErrors([
        { name: 'X-A', value: '1' },
        { name: 'x-a', value: '2' },
      ])
    ).toEqual({
      1: 'This header is already listed (names are not case-sensitive).',
    })
  })
  it('trims what it sends', () => {
    expect(normalizeHeaders([{ name: ' X-A ', value: ' 1 ' }])).toEqual([
      { name: 'X-A', value: '1' },
    ])
  })
})

describe('mergeIdentity', () => {
  const platform = {
    user_agent: 'openctem-scanner',
    user_agent_enforced: false,
    headers: [
      { name: 'X-Operator', value: 'saas', enforced: true },
      { name: 'X-Env', value: 'prod' },
    ],
  }
  it('keeps the union; the organization wins unless the platform enforces', () => {
    const e = mergeIdentity(platform, {
      userAgent: 'corp-scan',
      headers: [
        { name: 'x-operator', value: 'mine' },
        { name: 'x-env', value: 'uat' },
        { name: 'ATTT', value: 'is-here' },
      ],
    })
    expect(e.headers).toEqual([
      { name: 'X-Operator', value: 'saas', source: 'platform_enforced' },
      { name: 'x-env', value: 'uat', source: 'organization' },
      { name: 'ATTT', value: 'is-here', source: 'organization' },
    ])
    expect(e.overridden).toEqual(['x-operator'])
    expect(e.userAgent).toBe('corp-scan')
    expect(previewLines(e)).toEqual([
      'GET / HTTP/1.1',
      'Host: target.example',
      'User-Agent: corp-scan',
      'X-Operator: saas',
      'x-env: uat',
      'ATTT: is-here',
    ])
  })
  it('uses the platform User-Agent as a default, or always when enforced', () => {
    expect(mergeIdentity(platform, { userAgent: '', headers: [] }).userAgent).toBe(
      'openctem-scanner'
    )
    expect(
      mergeIdentity({ ...platform, user_agent_enforced: true }, { userAgent: 'corp', headers: [] })
        .userAgent
    ).toBe('openctem-scanner')
    expect(mergeIdentity(undefined, { userAgent: '', headers: [] }).headers).toEqual([])
  })
})

describe('User-Agent rotation list', () => {
  it('reads one value per line, trimmed, blank lines dropped', () => {
    expect(parseUserAgentList(' a/1 \n\n b/2\n')).toEqual(['a/1', 'b/2'])
  })
  it('flags each bad line by number: too long, not ASCII, duplicate', () => {
    const text = ['ok/1', 'x'.repeat(257), 'caf\u00e9', 'ok/1'].join('\n')
    expect(userAgentListErrors(text).map((e) => e.line)).toEqual([2, 3, 4])
  })
  it('refuses more than 200 values for the whole list', () => {
    const text = Array.from({ length: 201 }, (_, i) => `ua/${i}`).join('\n')
    const errs = userAgentListErrors(text)
    expect(errs[0].line).toBe(0)
    expect(userAgentListErrors(text.split('\n').slice(0, 200).join('\n'))).toEqual([])
  })
  it('refuses a single User-Agent together with a list', () => {
    expect(userAgentBothError('one', ['a'])).not.toBeNull()
    expect(userAgentBothError('', ['a'])).toBeNull()
  })
})

describe('query parameter', () => {
  it('accepts URL-safe parts and treats an empty pair as none', () => {
    expect(queryError({ name: 'scan', value: 'corp-1.a_b~c' })).toBeNull()
    expect(queryError({ name: ' ', value: '' })).toBeNull()
    expect(normalizeQuery({ name: '', value: '' })).toBeNull()
    expect(queryError({ name: 'a b', value: 'v' })).not.toBeNull()
    expect(queryError({ name: 'n', value: 'a&b=c' })).not.toBeNull()
    expect(queryError({ name: 'n', value: '' })).not.toBeNull()
  })
})

describe('rotation, query and required in the merge', () => {
  const platform = {
    user_agent: '',
    user_agents: ['p/1', 'p/2'],
    user_agent_enforced: false,
    headers: [],
    query: { name: 'scan', value: 'plat' },
    identification_required: true,
  }
  it('uses the winning list whole and ORs the requirement', () => {
    const e = mergeIdentity(platform, {
      userAgent: '',
      userAgents: ['o/1', 'o/2', 'o/3'],
      headers: [],
    })
    expect(e.userAgents).toEqual(['o/1', 'o/2', 'o/3'])
    expect(e.userAgent).toBe('o/1')
    expect(e.query).toEqual({ name: 'scan', value: 'plat' })
    expect(e.querySource).toBe('platform')
    expect(e.required).toBe(true)
    expect(e.requiredBy).toEqual(['platform'])
    expect(previewLines(e)[0]).toBe('GET /?scan=plat HTTP/1.1')
  })
  it('keeps an enforced platform list and query', () => {
    const e = mergeIdentity(
      { ...platform, user_agent_enforced: true, query_enforced: true },
      { userAgent: 'mine', headers: [], query: { name: 'scan', value: 'org' } }
    )
    expect(e.userAgents).toEqual(['p/1', 'p/2'])
    expect(e.userAgentSource).toBe('platform_enforced')
    expect(e.query?.value).toBe('plat')
  })
  it('reports required without a header or query parameter', () => {
    const none = mergeIdentity(undefined, { userAgent: '', headers: [], required: true })
    expect(none.requiredBy).toEqual(['organization'])
    expect(requiredWithoutMarker(none)).toBe(true)
    const withHeader = mergeIdentity(undefined, {
      userAgent: '',
      headers: [{ name: 'X-Scan', value: '1' }],
      required: true,
    })
    expect(requiredWithoutMarker(withHeader)).toBe(false)
    expect(requiredWithoutMarker(mergeIdentity(platform, { userAgent: '', headers: [] }))).toBe(
      false
    )
  })
})
