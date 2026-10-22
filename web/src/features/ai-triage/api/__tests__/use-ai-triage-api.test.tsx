import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

let perms: string[] = []
const get = vi.fn()
const handleApiError = vi.fn()

vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => get(...a), post: vi.fn() }))
vi.mock('@/lib/api/error-handler', () => ({
  handleApiError: (...a: unknown[]) => handleApiError(...a),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role: 'member' } }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissionsSafe: () => ({ hasPermission: (p: string) => perms.includes(p) }),
}))

const { useAIConfig, useTriageResult, useTriageHistory } = await import('../use-ai-triage-api')

const wrapper = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map() }}>{children}</SWRConfig>
)

describe('AI triage read hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    get.mockRejectedValue({ statusCode: 403 })
  })

  it('send no request and raise no error toast without ai_triage:read', async () => {
    perms = ['ai_triage:trigger']
    renderHook(
      () => {
        useAIConfig()
        useTriageResult('f1')
        useTriageHistory('f1')
      },
      { wrapper }
    )
    await new Promise((r) => setTimeout(r, 50))
    expect(get).not.toHaveBeenCalled()
    expect(handleApiError).not.toHaveBeenCalled()
  })

  it('read the config and the result with ai_triage:read', async () => {
    perms = ['ai_triage:read']
    get.mockResolvedValue({ data: null })
    renderHook(
      () => {
        useAIConfig()
        useTriageResult('f1')
      },
      { wrapper }
    )
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    const urls = get.mock.calls.map((c) => c[0])
    expect(urls).toContain('/api/v1/findings/ai-triage/config')
    expect(urls).toContain('/api/v1/findings/f1/ai-triage')
  })
})
