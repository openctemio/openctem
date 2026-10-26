import { describe, expect, it, vi } from 'vitest'
import { cveOf, paletteQuery, paletteSearchUrls, searchPalette } from '../palette-search'
import { requestedForm, openFormHref } from '@/lib/open-form'

const all = { findings: true, assets: true, tasks: true }

describe('paletteQuery', () => {
  it('needs two characters and never sends a command query', () => {
    expect(paletteQuery('a')).toBeNull()
    expect(paletteQuery('  ab ')).toBe('ab')
    expect(paletteQuery('> new scan')).toBeNull()
    expect(paletteQuery('x'.repeat(500))).toHaveLength(200)
  })
})

describe('cveOf', () => {
  it('recognises a CVE id typed as the query', () => {
    expect(cveOf(' cve-2026-41187 ')).toBe('CVE-2026-41187')
    expect(cveOf('CVE-2026')).toBeNull()
    expect(cveOf('log4j CVE-2021-44228')).toBeNull()
  })
})

describe('paletteSearchUrls', () => {
  it('queries only the types the caller may read', () => {
    expect(
      Object.keys(paletteSearchUrls('web', { findings: true, assets: false, tasks: false }))
    ).toEqual(['finding'])
    expect(paletteSearchUrls('web', { findings: false, assets: false, tasks: false })).toEqual({})
  })

  it('encodes the query and asks for five per type through the list APIs', () => {
    const u = paletteSearchUrls('a&b=c', all)
    expect(u.finding).toBe('/api/v1/findings?q=a%26b%3Dc&per_page=5')
    expect(u.asset).toBe('/api/v1/assets?search=a%26b%3Dc&per_page=5')
    expect(u.task).toContain('/api/v1/remediation/tasks?')
    expect(u.task).toContain('search=a%26b%3Dc')
    expect(u.task).toContain('per_page=5')
  })
})

describe('searchPalette', () => {
  it('maps rows to links, drops bad ids, keeps the other types when one fails', async () => {
    const fetcher = vi.fn(async (url: string) => {
      if (url.startsWith('/api/v1/findings')) {
        return {
          data: [
            { id: '00000000-0000-0000-0000-000000000001', title: 'SQL injection <b>x</b>' },
            { id: '../../admin', title: 'bad' },
          ],
        }
      }
      if (url.startsWith('/api/v1/assets')) throw new Error('403')
      return { data: [{ id: '00000000-0000-0000-0000-000000000002', title: 'Patch edge' }] }
    })
    const out = await searchPalette('sql', all, undefined, fetcher)
    expect(out.map((e) => [e.kind, e.href])).toEqual([
      ['finding', '/findings/00000000-0000-0000-0000-000000000001'],
      ['task', '/remediation/tasks/00000000-0000-0000-0000-000000000002'],
    ])
    // Scanner text stays text.
    expect(out[0].label).toBe('SQL injection <b>x</b>')
  })

  it('sends nothing for a type the caller may not read', async () => {
    const fetcher = vi.fn(async (_url: string) => ({ data: [] }))
    await searchPalette('sql', { findings: false, assets: true, tasks: false }, undefined, fetcher)
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(fetcher.mock.calls[0][0]).toContain('/api/v1/assets?')
  })
})

describe('open-a-form links', () => {
  it('names only known forms', () => {
    expect(openFormHref('/scans', 'scan')).toBe('/scans?new=scan')
    expect(requestedForm('?new=import')).toBe('import')
    expect(requestedForm('?new=delete-everything')).toBeNull()
    expect(requestedForm('')).toBeNull()
  })
})
