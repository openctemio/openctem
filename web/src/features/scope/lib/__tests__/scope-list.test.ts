import { describe, expect, it, vi } from 'vitest'
import {
  BULK_BATCH_SIZE,
  batchesOf,
  itemsOf,
  MAX_LIST_VALUES,
  parseScopeList,
  removeInvalidScopeValues,
  removeScopeValue,
  splitScopeValues,
  submitScopeBatches,
} from '../scope-list'

describe('splitScopeValues', () => {
  it('splits on newline, comma, semicolon, tab and space, and drops quotes and blanks', () => {
    expect(splitScopeValues('a.com, b.com;c.com\td.com\r\n"e.com"\n\n  f.com ')).toEqual([
      'a.com',
      'b.com',
      'c.com',
      'd.com',
      'e.com',
      'f.com',
    ])
  })
})

describe('parseScopeList', () => {
  it('detects each kind with the single-path detector', () => {
    const { rows } = parseScopeList(
      'acme.io 203.0.113.7 203.0.113.0/24 https://app.acme.io/x github.com/acme/web AWS:123456789012',
      'name'
    )
    expect(rows.map((r) => r.kind)).toEqual([
      'domain',
      'ip_address',
      'ip_range',
      'url',
      'repository',
      'cloud_account',
    ])
  })

  it('applies the Covers choice to every domain and only to domains', () => {
    const sub = parseScopeList('acme.io\n*.shop.acme.io\n203.0.113.7', 'subdomains').rows
    expect(sub.map((r) => r.pattern)).toEqual(['*.acme.io', '*.shop.acme.io', '203.0.113.7'])
    const name = parseScopeList('acme.io\n*.shop.acme.io\n203.0.113.7', 'name').rows
    expect(name.map((r) => r.pattern)).toEqual(['acme.io', 'shop.acme.io', '203.0.113.7'])
  })

  it('keeps a domain exact for a request', () => {
    const { rows } = parseScopeList('acme.io\nb.io', 'subdomains', { asRequest: true })
    expect(rows.map((r) => r.pattern)).toEqual(['acme.io', 'b.io'])
  })

  it('dedupes after normalising and counts the repeats', () => {
    const r = parseScopeList('Acme.io\nacme.io.\n*.acme.io\nb.io', 'subdomains')
    expect(r.rows.map((x) => x.pattern)).toEqual(['*.acme.io', '*.b.io'])
    expect(r.duplicates).toBe(2)
  })

  it('marks what is not recognised and keeps it out of the items', () => {
    const r = parseScopeList('acme.io\nfoo_bar\n999.1.1.1', 'name')
    expect(r.rows.filter((x) => x.issue === 'unrecognized').map((x) => x.raw)).toEqual([
      'foo_bar',
      '999.1.1.1',
    ])
    expect(itemsOf(r.rows)).toEqual([{ target_type: 'domain', pattern: 'acme.io' }])
  })

  it('refuses a list over the cap and parses nothing', () => {
    const text = Array.from({ length: MAX_LIST_VALUES + 1 }, (_, i) => `h${i}.acme.io`).join('\n')
    const r = parseScopeList(text, 'name')
    expect(r.tooMany).toBe(true)
    expect(r.total).toBe(MAX_LIST_VALUES + 1)
    expect(r.rows).toEqual([])
    expect(
      parseScopeList(text.split('\n').slice(0, MAX_LIST_VALUES).join('\n'), 'name').tooMany
    ).toBe(false)
  })
})

describe('removing values', () => {
  it('removes a value and its spellings from the text', () => {
    const row = parseScopeList('b.io', 'name').rows[0]
    expect(removeScopeValue('a.io, B.io\nb.io. c.io', row, 'name')).toBe('a.io\nc.io')
  })

  it('removes every value that is not recognised', () => {
    expect(removeInvalidScopeValues('a.io\nzzz\nb.io', 'name')).toBe('a.io\nb.io')
  })
})

describe('batching', () => {
  it('splits into requests of 200', () => {
    const items = Array.from({ length: 450 }, (_, i) => i)
    expect(batchesOf(items).map((b) => b.length)).toEqual([200, 200, 50])
    expect(BULK_BATCH_SIZE).toBe(200)
    expect(batchesOf([])).toEqual([])
  })

  const items = Array.from({ length: 450 }, (_, i) => ({
    target_type: 'domain',
    pattern: `h${i}.io`,
  }))
  const ok = (n: number) =>
    vi.fn(async (input: { items: { pattern: string }[] }) => ({
      results: input.items.map((i) => ({
        pattern: i.pattern,
        target_type: 'domain',
        result: 'created',
      })),
      created: input.items.length,
      existing: 0,
      refused: n,
    }))

  it('sends the batches one after the other with the shared settings and sums the counts', async () => {
    const send = ok(1)
    const out = await submitScopeBatches(items, { reason: 'r', expires_in_days: 7 }, send as never)
    expect(send).toHaveBeenCalledTimes(3)
    expect(send.mock.calls.map((c) => c[0].items.length)).toEqual([200, 200, 50])
    for (const c of send.mock.calls) expect(c[0]).toMatchObject({ reason: 'r', expires_in_days: 7 })
    expect(out).toMatchObject({ created: 450, refused: 3, existing: 0, unsent: [] })
    expect(out.results).toHaveLength(450)
  })

  it('throws when the first batch fails, nothing is reported as sent', async () => {
    const send = vi.fn().mockRejectedValue(new Error('step-up cancelled'))
    await expect(submitScopeBatches(items, {}, send)).rejects.toThrow('step-up cancelled')
    expect(send).toHaveBeenCalledTimes(1)
  })

  it('stops at a failed later batch and returns what was not sent', async () => {
    const good = ok(0)
    const send = vi.fn().mockImplementationOnce(good).mockRejectedValueOnce(new Error('boom'))
    const out = await submitScopeBatches(items, {}, send as never)
    expect(send).toHaveBeenCalledTimes(2)
    expect(out.created).toBe(200)
    expect(out.unsent).toHaveLength(250)
    expect(out.unsent[0].pattern).toBe('h200.io')
    expect((out.error as Error).message).toBe('boom')
  })
})
