import { describe, it, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

vi.mock('@/lib/api/client', () => ({ get: vi.fn(), post: vi.fn(), del: vi.fn() }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't' } }) }))

import { apiKeysListKey } from '../use-api-keys'

describe('API keys list paging (23a B20)', () => {
  it('asks the server for one page, 1-based', () => {
    const p = new URL(apiKeysListKey({ page: 6, perPage: 20 }), 'http://x').searchParams
    expect(p.get('page')).toBe('6')
    expect(p.get('per_page')).toBe('20')
  })

  it('never asks for page 0 and passes the search through', () => {
    const p = new URL(apiKeysListKey({ page: 0, search: 'ci' }), 'http://x').searchParams
    expect(p.get('page')).toBe('1')
    expect(p.get('search')).toBe('ci')
  })

  it('the page uses server pagination with the API total', () => {
    const src = readFileSync(
      join(process.cwd(), 'src/app/(dashboard)/settings/api-keys/page.tsx'),
      'utf8'
    )
    expect(src).toMatch(/manualPagination/)
    expect(src).toMatch(/rowCount=\{total\}/)
    expect(src).not.toMatch(/per_page=100/)
  })
})
