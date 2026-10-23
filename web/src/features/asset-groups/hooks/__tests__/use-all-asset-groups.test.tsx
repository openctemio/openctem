/**
 * The groups list searches, selects and exports across every group, so it
 * walks the pages (the API pages at 100) up to a cap and reports the real total.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const getMock = vi.hoisted(() => vi.fn())

vi.mock('@/lib/env', () => ({ env: { features: { useRealApi: true } } }))
vi.mock('@/lib/api/client', () => ({
  get: getMock,
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  del: vi.fn(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  Permission: { AssetGroupsRead: 'assets:groups:read' },
}))

import { useAllAssetGroups } from '../use-asset-groups'

const wrapper = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
)

function row(i: number) {
  return { id: `g${i}`, name: `group ${i}`, environment: 'production', criticality: 'high' }
}

function pageOf(page: number, perPage: number, total: number) {
  const start = (page - 1) * perPage
  const n = Math.max(0, Math.min(perPage, total - start))
  return { data: Array.from({ length: n }, (_, k) => row(start + k)), total }
}

beforeEach(() => getMock.mockReset())

describe('useAllAssetGroups', () => {
  it('loads every page, not only the first 20', async () => {
    getMock.mockImplementation(async (url: string) => {
      const q = new URL(url, 'http://x').searchParams
      return pageOf(Number(q.get('page')), Number(q.get('per_page')), 250)
    })
    const { result } = renderHook(() => useAllAssetGroups({ filters: { search: 'prod' } }), {
      wrapper,
    })
    await waitFor(() => expect(result.current.data).toHaveLength(250))
    expect(result.current.total).toBe(250)
    expect(result.current.truncated).toBe(false)
    expect(getMock).toHaveBeenCalledTimes(3)
    // The search goes to the server.
    expect(getMock.mock.calls[0][0]).toContain('search=prod')
  })

  it('stops at the cap and says the list is partial', async () => {
    getMock.mockImplementation(async (url: string) => {
      const q = new URL(url, 'http://x').searchParams
      return pageOf(Number(q.get('page')), Number(q.get('per_page')), 1500)
    })
    const { result } = renderHook(() => useAllAssetGroups({ filters: {} }), { wrapper })
    await waitFor(() => expect(result.current.data).toHaveLength(1000))
    expect(result.current.total).toBe(1500)
    expect(result.current.truncated).toBe(true)
    expect(result.current.cap).toBe(1000)
  })
})
