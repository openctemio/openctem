import { renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const swrState: { data?: unknown; isLoading: boolean } = { isLoading: false }

vi.mock('swr', () => ({
  default: () => ({ ...swrState, error: undefined, mutate: vi.fn() }),
}))
vi.mock('@/context/bootstrap-provider', () => ({
  useBootstrapContextOptional: () => null,
}))

import { useModuleEnabled } from '../use-tenant-modules'

describe('useModuleEnabled', () => {
  beforeEach(() => {
    swrState.data = undefined
    swrState.isLoading = false
  })

  it('is closed while the module list loads, so a switched-off module is never fetched', () => {
    swrState.isLoading = true
    const { result } = renderHook(() => useModuleEnabled('attack_simulation'))
    expect(result.current).toBe(false)
  })

  it('follows the loaded list', () => {
    swrState.data = { module_ids: ['pentest'], modules: [] }
    expect(renderHook(() => useModuleEnabled('pentest')).result.current).toBe(true)
    expect(renderHook(() => useModuleEnabled('attack_simulation')).result.current).toBe(false)
  })

  it('opens everything once the API has answered with no module list', () => {
    swrState.data = { module_ids: [], modules: [] }
    expect(renderHook(() => useModuleEnabled('attack_simulation')).result.current).toBe(true)
  })
})
