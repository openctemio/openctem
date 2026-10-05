/**
 * Members list paging (23a B20): the settings page pages, searches and
 * filters on the server, so a member past the first 100 is reachable.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import useSWR from 'swr'

vi.mock('swr', () => ({
  default: vi.fn(() => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() })),
}))
vi.mock('@/lib/api/client', () => ({ fetcher: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  Permission: { MembersRead: 'team:members:read' },
}))

import { useMembers } from '../use-members'

function lastParams(): URLSearchParams {
  const calls = vi.mocked(useSWR).mock.calls
  const key = calls[calls.length - 1][0] as string
  return new URL(key, 'http://x').searchParams
}

describe('useMembers server paging', () => {
  beforeEach(() => vi.mocked(useSWR).mockClear())

  it('sends limit/offset so the 6th page of 20 asks for members 101-120', () => {
    renderHook(() => useMembers('acme', { limit: 20, offset: 100 }))
    const p = lastParams()
    expect(p.get('limit')).toBe('20')
    expect(p.get('offset')).toBe('100')
  })

  it('sends status, role and search to the server', () => {
    renderHook(() =>
      useMembers('acme', { search: 'ada', status: 'suspended', role: 'admin', limit: 20 })
    )
    const p = lastParams()
    expect(p.get('search')).toBe('ada')
    expect(p.get('status')).toBe('suspended')
    expect(p.get('role')).toBe('admin')
  })
})

describe('settings members page', () => {
  const src = readFileSync(
    join(process.cwd(), 'src/app/(dashboard)/settings/members/page.tsx'),
    'utf8'
  )
  it('uses server pagination with the API total, not a browser-side filter', () => {
    expect(src).toMatch(/manualPagination/)
    expect(src).toMatch(/rowCount=\{membersTotal\}/)
    expect(src).not.toMatch(/filteredData/)
  })
})
