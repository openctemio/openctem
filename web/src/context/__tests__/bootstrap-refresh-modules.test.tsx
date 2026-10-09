/**
 * refreshModules re-reads only the organization's modules after a toggle, so
 * the sidebar and the route guard (which read the bootstrap set) follow at
 * once, without the loading state of a full bootstrap refresh.
 */
import * as React from 'react'
import { act, cleanup, render, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...args: unknown[]) => get(...args),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
}))
vi.mock('../tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 'tenant-a' } }),
}))
vi.mock('../bootstrap-session', () => ({ seedSessionCache: vi.fn(async () => {}) }))

import { BootstrapProvider, useBootstrapContext, useBootstrapModules } from '../bootstrap-provider'

describe('BootstrapProvider.refreshModules', () => {
  beforeEach(() => get.mockReset())
  afterEach(() => cleanup())

  it('replaces the module set without a loading state', async () => {
    get.mockImplementation(async (url: string) => {
      if (url === '/api/v1/me/bootstrap') {
        return {
          permissions: { list: [], version: 1 },
          modules: { module_ids: ['assets', 'pentest'], modules: [] },
        }
      }
      if (url === '/api/v1/me/modules') {
        return { module_ids: ['assets'], modules: [] }
      }
      return undefined
    })

    const seen: { ids: string[]; loading: boolean }[] = []
    let refresh: (() => Promise<void>) | undefined
    function Probe() {
      const ctx = useBootstrapContext()
      const { moduleIds } = useBootstrapModules()
      refresh = ctx.refreshModules
      seen.push({ ids: moduleIds, loading: ctx.isLoading })
      return null
    }
    render(
      <BootstrapProvider>
        <Probe />
      </BootstrapProvider>
    )
    await waitFor(() => expect(seen.at(-1)?.ids).toEqual(['assets', 'pentest']))
    const before = seen.length

    await act(async () => {
      await refresh?.()
    })

    expect(seen.at(-1)?.ids).toEqual(['assets'])
    expect(seen.slice(before).some((s) => s.loading)).toBe(false)
    expect(get).toHaveBeenCalledWith('/api/v1/me/modules')
  })

  it('keeps the current set when the read fails', async () => {
    get.mockImplementation(async (url: string) => {
      if (url === '/api/v1/me/bootstrap') {
        return {
          permissions: { list: [], version: 1 },
          modules: { module_ids: ['assets'], modules: [] },
        }
      }
      if (url === '/api/v1/me/modules') throw new Error('down')
      return undefined
    })
    let ids: string[] = []
    let refresh: (() => Promise<void>) | undefined
    function Probe() {
      refresh = useBootstrapContext().refreshModules
      ids = useBootstrapModules().moduleIds
      return null
    }
    render(
      <BootstrapProvider>
        <Probe />
      </BootstrapProvider>
    )
    await waitFor(() => expect(ids).toEqual(['assets']))
    await act(async () => {
      await refresh?.()
    })
    expect(ids).toEqual(['assets'])
  })
})
