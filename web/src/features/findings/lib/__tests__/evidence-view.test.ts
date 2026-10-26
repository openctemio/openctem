import { describe, expect, it } from 'vitest'
import type { EvidenceItem } from '@/lib/api/generated'
import {
  byteToCharIndex,
  foldEvidence,
  primaryEvidence,
  placeholdersOf,
  rawRequestText,
  rawResponseText,
  segmentBody,
  splitPlaceholders,
  substitute,
} from '../evidence-view'

const item: EvidenceItem = {
  kind: 'http_exchange',
  http: {
    request: {
      method: 'GET',
      url: 'https://h.example/admin?x=1',
      http_version: 'HTTP/1.1',
      headers: [
        { name: 'Host', value: 'h.example' },
        { name: 'Authorization', value: 'Bearer «secret:authorization#1»' },
      ],
    },
    response: {
      status: 200,
      reason: 'OK',
      headers: [{ name: 'Content-Type', value: 'text/html' }],
      body: '<script>alert(1)</script> café version 7.1.0',
    },
  },
  match: [{ location: 'response', part: 'body', start: 40, end: 45 }],
}

describe('evidence view helpers', () => {
  it('converts UTF-8 byte offsets to string indexes', () => {
    const s = 'café 7.1.0'
    expect(byteToCharIndex(s, 6)).toBe(5) // "é" is 2 bytes
    expect(s.slice(byteToCharIndex(s, 6))).toBe('7.1.0')
    expect(byteToCharIndex('a😀b', 5)).toBe(3) // the emoji is 4 bytes, 2 UTF-16 units
  })

  it('marks the matched bytes, even after multi-byte characters', () => {
    const segs = segmentBody(item.http!.response!.body!, [[40, 45]])
    const marked = segs.filter((s) => s.mark)
    expect(marked).toEqual([{ kind: 'text', text: '7.1.0', mark: true }])
    // The script stays plain text: segments carry strings, never markup.
    expect(segs[0]).toEqual({
      kind: 'text',
      text: '<script>alert(1)</script> café version ',
      mark: false,
    })
  })

  it('ignores invalid ranges and merges overlapping ones', () => {
    expect(
      segmentBody('abcdef', [
        [4, 2],
        [-1, 3],
        [NaN, 2],
      ]).every((s) => !s.mark)
    ).toBe(true)
    const segs = segmentBody('abcdef', [
      [1, 3],
      [2, 5],
    ])
    expect(segs.filter((s) => s.mark).map((s) => (s.kind === 'text' ? s.text : ''))).toEqual([
      'bcde',
    ])
  })

  it('splits placeholders out of text', () => {
    expect(splitPlaceholders('Bearer «secret:authorization#1» x')).toEqual([
      { kind: 'text', text: 'Bearer ', mark: false },
      { kind: 'secret', placeholder: '«secret:authorization#1»', mark: false },
      { kind: 'text', text: ' x', mark: false },
    ])
    // A look-alike that is not the grammar stays text.
    expect(splitPlaceholders('«secret:BAD#x»')).toEqual([
      { kind: 'text', text: '«secret:BAD#x»', mark: false },
    ])
  })

  it('lists placeholders once', () => {
    expect(placeholdersOf(item)).toEqual(['«secret:authorization#1»'])
  })

  it('builds raw HTTP text', () => {
    expect(rawRequestText(item)).toBe(
      'GET /admin?x=1 HTTP/1.1\r\nHost: h.example\r\nAuthorization: Bearer «secret:authorization#1»\r\n\r\n'
    )
    expect(
      rawResponseText(item).startsWith('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>')
    ).toBe(true)
  })

  it('substitutes revealed values, quoting them for a shell', () => {
    const curl = "curl -H 'Authorization: Bearer «secret:authorization#1»' 'https://h'"
    const v = { '«secret:authorization#1»': "tok'$(id)" }
    expect(substitute(curl, v, true)).toBe(
      "curl -H 'Authorization: Bearer tok'\\''$(id)' 'https://h'"
    )
    expect(substitute('a «secret:token#9» b', v)).toBe('a «secret:token#9» b')
  })
})

describe('evidence grouping', () => {
  const t0 = '2026-10-20T10:00:00.000Z'
  const t1 = '2026-10-20T10:00:02.000Z'
  const later = '2026-10-21T08:00:00.000Z'
  const ex = (id: string, created_at: string, origin = 'detection', retest_id?: string) => ({
    id,
    kind: 'http_exchange',
    origin,
    retest_id,
    created_at,
    curl: "curl 'https://h/'",
  })
  const curl = (id: string, created_at: string, origin = 'detection', retest_id?: string) => ({
    id,
    kind: 'curl',
    origin,
    retest_id,
    created_at,
  })

  it('drops the curl item of the same capture, keeps others', () => {
    const items = [curl('c1', t1), ex('e1', t0), curl('c-alone', later, 'retest', 'r1')]
    expect(foldEvidence(items).map((r) => r.id)).toEqual(['e1', 'c-alone'])
  })

  it('does not fold a curl item into a different retest attempt', () => {
    const items = [curl('c1', t0, 'retest', 'r2'), ex('e1', t0, 'retest', 'r1')]
    expect(foldEvidence(items).map((r) => r.id)).toEqual(['c1', 'e1'])
  })

  it('picks the HTTP exchange of the newest detection, not its curl item', () => {
    const items = [curl('c2', later), ex('e2', later), curl('c1', t1), ex('e1', t0)]
    expect(primaryEvidence(items)?.id).toBe('e2')
  })

  it('prefers a detection over a newer retest attempt', () => {
    const items = [ex('r', later, 'retest', 'r1'), ex('d', t0)]
    expect(primaryEvidence(items)?.id).toBe('d')
  })

  it('falls back to whatever exists', () => {
    expect(primaryEvidence([curl('c', t0)])?.id).toBe('c')
    expect(primaryEvidence([])).toBeUndefined()
  })
})
