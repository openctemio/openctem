/**
 * A disabled useAssetGroups (a closed Edit scan dialog, a rule dialog on
 * another rule type) must send no request. It used to pass `undefined`
 * filters down, which built the unfiltered GET /asset-groups key, so every
 * page that mounts such a dialog paid one list request on load.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import useSWR from 'swr'

vi.mock('swr', () => ({
  default: vi.fn(() => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() })),
}))
vi.mock('swr/mutation', () => ({ default: vi.fn(() => ({ trigger: vi.fn() })) }))
vi.mock('@/lib/env', () => ({ env: { features: { useRealApi: true } } }))
vi.mock('@/lib/api/client', () => ({
  get: vi.fn(),
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

import { useAssetGroups } from '../use-asset-groups'
import { useAssetGroupsApi } from '../../api/use-asset-groups-api'

function keys(): unknown[] {
  return vi.mocked(useSWR).mock.calls.map((c) => c[0])
}

describe('useAssetGroups only fetches when enabled', () => {
  beforeEach(() => vi.mocked(useSWR).mockClear())

  it('disabled: no request key at all', () => {
    renderHook(() => useAssetGroups({ filters: { per_page: 100 }, enabled: false }))
    expect(keys()).toEqual([null])
  })

  it('disabled without filters: still no request', () => {
    renderHook(() => useAssetGroups({ enabled: false }))
    expect(keys()).toEqual([null])
  })

  it('enabled: fetches with its filters', () => {
    renderHook(() => useAssetGroups({ filters: { per_page: 100 } }))
    expect(keys()).toEqual(['/api/v1/asset-groups?per_page=100'])
  })

  it('enabled without filters: the whole list, as before', () => {
    renderHook(() => useAssetGroups())
    expect(keys()).toEqual(['/api/v1/asset-groups'])
  })

  it('useAssetGroupsApi(null) sends nothing', () => {
    renderHook(() => useAssetGroupsApi(null))
    expect(keys()).toEqual([null])
  })
})
