/**
 * Asset names on the threat-model page come from one list request per 100 ids
 * (GET /assets?ids=…), not one GET /assets/{id} per asset (research/81).
 */
import * as React from 'react'
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => get(...a) }))

import { ASSET_NAME_BATCH, assetNamesURL, useAssetNameMap } from '../use-threat-model-refs'

function wrapper({ children }: { children: React.ReactNode }) {
  return (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
  )
}

const id = (n: number) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`

describe('useAssetNameMap', () => {
  beforeEach(() => get.mockReset())

  it('resolves every name with one request', async () => {
    get.mockResolvedValue({
      data: [
        { id: id(1), name: 'a.example.com' },
        { id: id(2), name: 'b.example.com' },
      ],
      total: 2,
    })
    const { result } = renderHook(() => useAssetNameMap([id(2), id(1), id(1)]), { wrapper })
    await waitFor(() => expect(result.current.nameFor(id(1))).toBe('a.example.com'))
    expect(result.current.nameFor(id(2))).toBe('b.example.com')
    expect(get).toHaveBeenCalledTimes(1)
    expect(get).toHaveBeenCalledWith(assetNamesURL([id(1), id(2)]))
    expect(get.mock.calls[0][0]).not.toMatch(/\/assets\/[0-9a-f-]{36}$/)
  })

  it('splits more than one page of ids into batches', async () => {
    get.mockResolvedValue({ data: [], total: 0 })
    const ids = Array.from({ length: ASSET_NAME_BATCH + 1 }, (_, i) => id(i + 1))
    renderHook(() => useAssetNameMap(ids), { wrapper })
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
  })

  it('an asset the caller may not see falls back to a short id', async () => {
    get.mockResolvedValue({ data: [], total: 0 })
    const { result } = renderHook(() => useAssetNameMap([id(9)]), { wrapper })
    await waitFor(() => expect(get).toHaveBeenCalled())
    expect(result.current.nameFor(id(9))).toBe(`${id(9).slice(0, 8)}…`)
  })

  it('sends nothing without ids', () => {
    renderHook(() => useAssetNameMap([]), { wrapper })
    expect(get).not.toHaveBeenCalled()
  })
})
