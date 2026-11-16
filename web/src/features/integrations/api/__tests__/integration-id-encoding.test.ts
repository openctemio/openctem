import { renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const keys: unknown[] = []

vi.mock('swr', () => ({
  default: (key: unknown) => {
    keys.push(key)
    return { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }
  },
}))
vi.mock('swr/mutation', () => ({
  default: (key: unknown) => {
    keys.push(key)
    return { trigger: vi.fn(), isMutating: false }
  },
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('@/lib/api/client', () => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  del: vi.fn(),
}))
vi.mock('@/lib/api/error-handler', () => ({ handleApiError: vi.fn() }))
vi.mock('../use-tenant-modules', () => ({ useTenantModules: () => ({ data: undefined }) }))

import {
  useNotificationEventsApi,
  useIntegrationApi,
  integrationIdFromParam,
} from '../use-integrations-api'
import { useTicketCreatePolicy } from '../use-ticket-create-policy'

const hostile = '../findings?x=1#'

describe('an integration id from the address is one path segment', () => {
  beforeEach(() => {
    keys.length = 0
  })

  it('notification events', () => {
    renderHook(() => useNotificationEventsApi(hostile, { limit: 10 }))
    const key = String(keys[0])
    expect(
      key.startsWith('/api/v1/integrations/..%2Ffindings%3Fx%3D1%23/notification-events')
    ).toBe(true)
    expect(key).not.toContain('/findings?')
  })

  it('a single integration', () => {
    renderHook(() => useIntegrationApi(hostile))
    expect(keys[0]).toBe('/api/v1/integrations/..%2Ffindings%3Fx%3D1%23')
  })

  it('the ticket creation policy', () => {
    renderHook(() => useTicketCreatePolicy(hostile))
    expect(String(keys[0])).toBe(
      '/api/v1/integrations/..%2Ffindings%3Fx%3D1%23/ticket-create-policy'
    )
  })

  it('only a UUID is taken from the address for the history page', () => {
    expect(integrationIdFromParam('0191c2b4-7a1e-7d3a-8f10-2b6a9c4d5e6f')).toBe(
      '0191c2b4-7a1e-7d3a-8f10-2b6a9c4d5e6f'
    )
    expect(integrationIdFromParam(hostile)).toBe('')
    expect(integrationIdFromParam(null)).toBe('')
  })
})
