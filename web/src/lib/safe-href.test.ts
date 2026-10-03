/**
 * Output encoding for data-driven links (RFC-040 §5.4). Every payload in
 * XSS_PAYLOADS is a value a hostile scan target or sensor can put in a
 * finding reference, an evidence URI or an asset URL; none of them may come
 * back as something a browser would run or navigate off-site with.
 */
import { describe, expect, it } from 'vitest'

import { MAX_URL_LENGTH, safeHref, safeImageSrc, safeInternalHref } from './safe-href'

const XSS_PAYLOADS: readonly string[] = [
  'javascript:alert(1)',
  'JavaScript:alert(1)',
  'JAVASCRIPT:alert(document.cookie)',
  ' javascript:alert(1)',
  '\tjavascript:alert(1)',
  '\njavascript:alert(1)',
  '\u0000javascript:alert(1)',
  '\u0001javascript:alert(1)',
  'java\tscript:alert(1)',
  'java\nscript:alert(1)',
  'java\rscript:alert(1)',
  'javascript\t:alert(1)',
  'javascript://example.com/%0Aalert(1)',
  'javascript:/*https://example.com*/alert(1)',
  '&#106;avascript:alert(1)',
  '&#x6A;avascript:alert(1)',
  '%6Aavascript:alert(1)',
  'jav&#x09;ascript:alert(1)',
  '\u200Bjavascript:alert(1)',
  'data:text/html,<script>alert(1)</script>',
  'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
  'DATA:text/html,<script>alert(1)</script>',
  ' data:text/html,<script>alert(1)</script>',
  'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+',
  'vbscript:msgbox(1)',
  'VBScript:msgbox(1)',
  'file:///etc/passwd',
  'blob:https://evil.test/uuid',
  'filesystem:https://evil.test/x',
  'about:blank',
  'chrome://settings',
  'ms-settings:',
  'jar:https://evil.test/x.jar!/',
  'livescript:alert(1)',
  '//evil.test/x',
  '///evil.test/x',
  '/\\evil.test/x',
  '\\\\evil.test\\x',
  '\\/evil.test',
  ' //evil.test',
  'https://evil.test/\u202Etxt.exe',
  'https://exa\u200Bmple.com/',
  'https:',
  'https://',
]

describe('safeHref — XSS payload list', () => {
  it.each(XSS_PAYLOADS)('refuses %j', (payload) => {
    expect(safeHref(payload)).toBeUndefined()
    expect(safeHref(payload, { allowMailto: true })).toBeUndefined()
  })
})

describe('safeHref — allowed values', () => {
  it.each([
    ['https://nvd.nist.gov/vuln/detail/CVE-2024-1', 'https://nvd.nist.gov/vuln/detail/CVE-2024-1'],
    ['http://example.com/', 'http://example.com/'],
    ['HTTPS://Example.COM/a?b=1#c', 'https://example.com/a?b=1#c'],
    ['  https://example.com/x  ', 'https://example.com/x'],
    ['https://exam\nple.com/', 'https://example.com/'],
    ['github.com/x/y', 'https://github.com/x/y'],
    ['example.com:8443/x', 'https://example.com:8443/x'],
    ['https://example.com/a b', 'https://example.com/a%20b'],
  ])('allows %j', (input, want) => {
    expect(safeHref(input)).toBe(want)
  })

  it('keeps same-origin paths unless told not to', () => {
    expect(safeHref('/api/v1/attachments/1/download')).toBe('/api/v1/attachments/1/download')
    expect(safeHref('#section')).toBe('#section')
    expect(safeHref('?tab=x')).toBe('?tab=x')
    expect(safeHref('/findings/1', { allowRelative: false })).toBeUndefined()
  })

  it('allows mailto only on request', () => {
    expect(safeHref('mailto:sec@example.com')).toBeUndefined()
    expect(safeHref('mailto:sec@example.com', { allowMailto: true })).toBe('mailto:sec@example.com')
  })

  it('refuses non-strings, empty and over-long values', () => {
    for (const v of [undefined, null, 42, {}, [], '', '   ']) {
      expect(safeHref(v)).toBeUndefined()
    }
    expect(safeHref(`https://example.com/${'a'.repeat(MAX_URL_LENGTH)}`)).toBeUndefined()
  })

  it('refuses scheme-less strings that are not host names', () => {
    expect(safeHref('./relative')).toBeUndefined()
    expect(safeHref('not a url')).toBeUndefined()
    expect(safeHref('localhost')).toBeUndefined()
  })
})

describe('safeImageSrc', () => {
  it('allows http(s), paths and raster data URLs', () => {
    expect(safeImageSrc('https://avatars.example.com/u/1')).toBe('https://avatars.example.com/u/1')
    expect(safeImageSrc('/api/v1/attachments/1')).toBe('/api/v1/attachments/1')
    expect(safeImageSrc('data:image/png;base64,iVBORw0KGgo=')).toBe(
      'data:image/png;base64,iVBORw0KGgo='
    )
  })

  it.each([
    ...XSS_PAYLOADS.filter((p) => !p.startsWith('blob:')),
    'data:image/svg+xml,<svg onload=alert(1)>',
    'data:image/png,<script>',
    'data:image/png;base64,"><script>',
  ])('refuses %j', (payload) => {
    expect(safeImageSrc(payload)).toBeUndefined()
  })

  it('allows blob: URLs from this origin only', () => {
    expect(safeImageSrc(`blob:${window.location.origin}/abc`)).toBe(
      `blob:${window.location.origin}/abc`
    )
    expect(safeImageSrc('blob:https://evil.test/abc')).toBeUndefined()
  })
})

describe('safeInternalHref', () => {
  it('allows same-origin paths only', () => {
    expect(safeInternalHref('/findings/1?tab=evidence')).toBe('/findings/1?tab=evidence')
    expect(safeInternalHref('https://evil.test/')).toBeUndefined()
    expect(safeInternalHref('//evil.test/')).toBeUndefined()
    expect(safeInternalHref('/\\evil.test/')).toBeUndefined()
    expect(safeInternalHref('javascript:alert(1)')).toBeUndefined()
    expect(safeInternalHref(' /findings/1')).toBe('/findings/1')
    expect(safeInternalHref(null)).toBeUndefined()
  })
})
