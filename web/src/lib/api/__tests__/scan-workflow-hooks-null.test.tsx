import { afterEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const client = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('../client', async (orig) => ({ ...(await orig<object>()), ...client }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't' } }) }))

import { useScanWorkflows } from '../scan-workflow-hooks'

afterEach(() => vi.clearAllMocks())

const fresh = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
)

describe('useScanWorkflows', () => {
  it('sends no request for null filters (a closed dialog costs the page nothing)', async () => {
    client.get.mockResolvedValue({ data: [], total: 0 })
    const { result } = renderHook(() => useScanWorkflows(null), { wrapper: fresh })
    await new Promise((r) => setTimeout(r, 100))
    expect(client.get).not.toHaveBeenCalled()
    expect(result.current.data).toBeUndefined()
  })

  it('lists every workflow for undefined filters', async () => {
    client.get.mockResolvedValue({ data: [], total: 0 })
    renderHook(() => useScanWorkflows(), { wrapper: fresh })
    await waitFor(() => expect(client.get).toHaveBeenCalledTimes(1))
    expect(String(client.get.mock.calls[0][0])).toContain('/scan-workflows')
  })
})
