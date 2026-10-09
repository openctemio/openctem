import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'

let swr: { data?: { tenant_creation_mode?: string }; error?: unknown; isLoading: boolean }
let providersEnabled: boolean[] = []
vi.mock('../../api/use-auth-providers', () => ({
  useAuthProviders: (_c: unknown, enabled = true) => {
    providersEnabled.push(enabled)
    return swr
  },
}))
let bootstrap: { isLoading: boolean; data: { tenant_creation_mode?: string } | null } | null = null
vi.mock('@/context/bootstrap-provider', () => ({ useBootstrapContextOptional: () => bootstrap }))

import { useCanCreateOrganization } from '../use-can-create-organization'

const run = () => renderHook(() => useCanCreateOrganization()).result.current

describe('useCanCreateOrganization', () => {
  beforeEach(() => {
    swr = { isLoading: false }
    bootstrap = null
    providersEnabled = []
  })

  it('offers nothing while the policy loads', () => {
    swr = { isLoading: true }
    expect(run()).toEqual({ canCreate: false, isLoading: true })
  })

  it('follows the server policy', () => {
    swr = { isLoading: false, data: { tenant_creation_mode: 'admin_only' } }
    expect(run().canCreate).toBe(false)
    swr = { isLoading: false, data: { tenant_creation_mode: 'self_service' } }
    expect(run().canCreate).toBe(true)
  })

  it('treats a rate-limited answer as still loading, not as self-service', () => {
    swr = { isLoading: false, error: { statusCode: 429 } }
    expect(run()).toEqual({ canCreate: false, isLoading: true })
  })

  it('offers creation when the policy cannot be fetched for another reason', () => {
    swr = { isLoading: false, error: { statusCode: 500 } }
    expect(run()).toEqual({ canCreate: true, isLoading: false })
  })

  it('inside the app shell, reads the policy from the session bootstrap and never asks /auth/providers', () => {
    bootstrap = { isLoading: false, data: { tenant_creation_mode: 'admin_only' } }
    expect(run()).toEqual({ canCreate: false, isLoading: false })
    bootstrap = { isLoading: false, data: { tenant_creation_mode: 'self_service' } }
    expect(run()).toEqual({ canCreate: true, isLoading: false })
    expect(providersEnabled.every((e) => e === false)).toBe(true)
  })

  it('waits for the bootstrap instead of asking in parallel', () => {
    bootstrap = { isLoading: true, data: null }
    expect(run()).toEqual({ canCreate: false, isLoading: true })
    expect(providersEnabled).toEqual([false])
  })

  it('falls back to /auth/providers when the bootstrap did not carry the policy', () => {
    bootstrap = { isLoading: false, data: {} }
    swr = { isLoading: false, data: { tenant_creation_mode: 'self_service' } }
    expect(run().canCreate).toBe(true)
    expect(providersEnabled).toEqual([true])
  })
})
