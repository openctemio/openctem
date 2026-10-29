/**
 * The bootstrap carries the organization's SLA windows, the AI setup and the
 * active support grants, so no page asks for them separately. A caller who
 * may not read one gets no field and the hook keeps its own request.
 */
import { cleanup, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { invalidateBootstrapSla, seedSessionCache } from '../bootstrap-session'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...args: unknown[]) => get(...args),
  post: vi.fn(),
  put: vi.fn(),
  del: vi.fn(),
  patch: vi.fn(),
  fetcher: (...args: unknown[]) => get(...args),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissionsSafe: () => ({ hasPermission: () => true }),
}))

const policy = { id: '', name: 'Platform defaults', critical_days: 7 } as never

describe('bootstrap shared reads', () => {
  beforeEach(() => get.mockReset())
  afterEach(() => cleanup())

  it('an asset resolves its windows from the bootstrap when no asset has an override', async () => {
    const { useEffectiveSlaPolicy } = await import('@/features/sla/api/use-sla-policies-api')
    await seedSessionCache({ sla: { policy, asset_overrides: false } })
    const { result } = renderHook(() => useEffectiveSlaPolicy('a1'))
    expect(result.current.data).toMatchObject({ critical_days: 7 })
    expect(get).not.toHaveBeenCalled()
  })

  it('with an asset override or no SLA field, the per-asset read stays', async () => {
    const { useEffectiveSlaPolicy } = await import('@/features/sla/api/use-sla-policies-api')
    get.mockResolvedValue({ critical_days: 1 })
    await seedSessionCache({ sla: { policy, asset_overrides: true } })
    renderHook(() => useEffectiveSlaPolicy('a2'))
    await waitFor(() => expect(get).toHaveBeenCalledWith('/api/v1/assets/a2/sla-policy'))

    get.mockClear()
    await seedSessionCache({})
    renderHook(() => useEffectiveSlaPolicy('a3'))
    await waitFor(() => expect(get).toHaveBeenCalledWith('/api/v1/assets/a3/sla-policy'))
  })

  it('a changed SLA policy clears the bootstrap windows', async () => {
    const { useEffectiveSlaPolicy } = await import('@/features/sla/api/use-sla-policies-api')
    get.mockResolvedValue({ critical_days: 2 })
    await seedSessionCache({ sla: { policy, asset_overrides: false } })
    await invalidateBootstrapSla()
    renderHook(() => useEffectiveSlaPolicy('a4'))
    await waitFor(() => expect(get).toHaveBeenCalledWith('/api/v1/assets/a4/sla-policy'))
  })

  it('a seeded AI setup is read from the cache without a request', async () => {
    const { useAIConfig } = await import('@/features/ai-triage/api/use-ai-triage-api')
    await seedSessionCache({
      ai_config: {
        mode: 'platform',
        provider: 'p',
        model: 'm',
        is_enabled: true,
        auto_triage_enabled: false,
        monthly_token_limit: 0,
        tokens_used_this_month: 0,
      },
    })
    const { result } = renderHook(() => useAIConfig())
    expect(result.current.data).toMatchObject({ isEnabled: true, mode: 'platform' })
    expect(get).not.toHaveBeenCalled()
  })

  it('seeded support grants are read by the banner hook without a request', async () => {
    const { useActiveSupportAccess } =
      await import('@/features/support-access/api/use-support-access')
    await seedSessionCache({
      support_access: { data: [{ admin_name: 'Support', scopes: ['findings'] }] } as never,
    })
    const { result } = renderHook(() => useActiveSupportAccess())
    expect(result.current).toHaveLength(1)
    expect(get).not.toHaveBeenCalled()
  })
})
