import { describe, expect, it, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import React from 'react'

const client = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('../client', () => client)
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 'org-1' } }),
}))

import { useSensorInstallTemplates } from '../sensor-pairing-hooks'

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
)

describe('useSensorInstallTemplates', () => {
  beforeEach(() => {
    client.get.mockReset().mockResolvedValue({ docker: 'x' })
    client.post.mockReset().mockResolvedValue({ docker: 'y' })
  })

  it('reads the code-less commands with GET and never POSTs on load', async () => {
    const { result } = renderHook(() => useSensorInstallTemplates<{ docker: string }>(null), {
      wrapper,
    })
    await waitFor(() => expect(result.current.data).toBeDefined())
    expect(client.get).toHaveBeenCalledWith('/api/v1/sensors/install-templates')
    expect(client.post).not.toHaveBeenCalled()
  })

  it('POSTs only when a code exists, with the code in the body', async () => {
    const { result } = renderHook(
      () => useSensorInstallTemplates<{ docker: string }>('K7QM-4ZTD'),
      {
        wrapper,
      }
    )
    await waitFor(() => expect(result.current.data).toBeDefined())
    expect(client.post).toHaveBeenCalledWith('/api/v1/sensors/install-templates', {
      pairing_code: 'K7QM-4ZTD',
    })
    expect(client.get).not.toHaveBeenCalled()
  })
})
