/**
 * Settings saves carry the section ETag from the cached GET /settings as
 * If-Match, so the API can refuse (409 SETTINGS_CONFLICT) a save that would
 * overwrite a change someone else made since this page loaded.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const fetcherWithOptions = vi.fn()
vi.mock('@/lib/api/client', () => ({
  fetcher: vi.fn(),
  fetcherWithOptions: (...args: unknown[]) => fetcherWithOptions(...args),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  Permission: { TeamRead: 'team:read' },
}))

import { tenantEndpoints } from '@/lib/api/endpoints'
import { isSettingsConflict, useUpdateSecuritySettings } from '../use-tenant-settings'

function makeWrapper(cache: Map<string, unknown>) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <SWRConfig value={{ provider: () => cache as never, dedupingInterval: 0 }}>
        {children}
      </SWRConfig>
    )
  }
}

describe('useUpdateSecuritySettings', () => {
  beforeEach(() => fetcherWithOptions.mockReset())

  it('sends the cached security ETag as If-Match', async () => {
    const cache = new Map<string, unknown>()
    cache.set(tenantEndpoints.settings('acme'), {
      data: { etags: { security: '"sec-1"', general: '"gen-1"' } },
    })
    fetcherWithOptions.mockResolvedValueOnce({ etags: { security: '"sec-2"' } })

    const { result } = renderHook(() => useUpdateSecuritySettings('acme'), {
      wrapper: makeWrapper(cache),
    })
    await act(async () => {
      await result.current.updateSecuritySettings({ mfa_required: true })
    })

    expect(fetcherWithOptions).toHaveBeenCalledWith(
      tenantEndpoints.updateSecuritySettings('acme'),
      expect.objectContaining({ method: 'PATCH', headers: { 'If-Match': '"sec-1"' } })
    )
  })

  it('sends no If-Match when the settings were never loaded', async () => {
    fetcherWithOptions.mockResolvedValueOnce({})
    const { result } = renderHook(() => useUpdateSecuritySettings('acme'), {
      wrapper: makeWrapper(new Map()),
    })
    await act(async () => {
      await result.current.updateSecuritySettings({ mfa_required: false })
    })
    expect(fetcherWithOptions.mock.calls[0][1].headers).toBeUndefined()
  })

  it('re-throws a conflict so the page can report it', async () => {
    const cache = new Map<string, unknown>()
    cache.set(tenantEndpoints.settings('acme'), { data: { etags: { security: '"old"' } } })
    const conflict = Object.assign(new Error('changed by someone else'), {
      code: 'SETTINGS_CONFLICT',
      statusCode: 409,
    })
    fetcherWithOptions.mockRejectedValueOnce(conflict)

    const { result } = renderHook(() => useUpdateSecuritySettings('acme'), {
      wrapper: makeWrapper(cache),
    })
    let caught: unknown
    await act(async () => {
      try {
        await result.current.updateSecuritySettings({ mfa_required: false })
      } catch (err) {
        caught = err
      }
    })
    expect(isSettingsConflict(caught)).toBe(true)
  })
})
