/**
 * The Approvals sidebar badge comes from the session bootstrap
 * (`badges.pending_approvals`): a page load must not ask GET /approvals for
 * it again. Without a seed (an older API, a failed count) it fetches as
 * before; a decision on the inbox refreshes it.
 */
import * as React from 'react'
import { cleanup, render, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...args: unknown[]) => get(...args),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('@/context/bootstrap-provider', () => ({ useBootstrapPending: () => false }))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  Permission: new Proxy({}, { get: (_t, k) => String(k) }),
}))
vi.mock('@/lib/env', () => ({ env: { features: { sidebarBadges: false } } }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: ['findings'] }),
}))
vi.mock('@/features/credentials/api', () => ({
  useCredentialStatsApi: () => ({ data: undefined }),
}))
vi.mock('@/features/attack-surface/hooks/use-easm-suggestions', () => ({
  useEASMSuggestionCount: () => undefined,
}))

import { PENDING_APPROVALS_COUNT_URL, seedSessionCache } from '@/context/bootstrap-session'
import { refreshPendingApprovalCount, useDynamicBadges } from '../use-dynamic-badges'

function Probe() {
  const badges = useDynamicBadges()
  return <span data-testid="approvals">{badges['/findings/approvals'] ?? ''}</span>
}

describe('Approvals badge', () => {
  beforeEach(() => get.mockReset())
  afterEach(() => cleanup())

  it('uses the key the bootstrap seeds', () => {
    expect(PENDING_APPROVALS_COUNT_URL).toBe('/api/v1/approvals?status=pending&page=1&per_page=1')
  })

  it('reads the seeded count without a request, and refreshes on demand', async () => {
    await seedSessionCache({ badges: { pending_approvals: 3 } })
    const { getByTestId } = render(<Probe />)
    await waitFor(() => expect(getByTestId('approvals').textContent).toBe('3'))
    expect(get).not.toHaveBeenCalled()

    get.mockResolvedValue({ status_counts: { pending: 2 } })
    await refreshPendingApprovalCount()
    expect(get).toHaveBeenCalledWith(PENDING_APPROVALS_COUNT_URL)
    await waitFor(() => expect(getByTestId('approvals').textContent).toBe('2'))
  })
})
