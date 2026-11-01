import { describe, expect, it } from 'vitest'
import {
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
    const e = mergeIdentity(platform, 'corp-scan', [
      { name: 'x-operator', value: 'mine' },
      { name: 'x-env', value: 'uat' },
      { name: 'ATTT', value: 'is-here' },
    ])
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
    expect(mergeIdentity(platform, '', []).userAgent).toBe('openctem-scanner')
    expect(mergeIdentity({ ...platform, user_agent_enforced: true }, 'corp', []).userAgent).toBe(
      'openctem-scanner'
    )
    expect(mergeIdentity(undefined, '', []).headers).toEqual([])
  })
})
