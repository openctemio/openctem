import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  CITrustScopeEntries,
  adoptScopeRequest,
  manageScopeSupported,
} from '../components/ci-trust-scope'
import { ciTrustManaged } from '@/features/scope/components/scope-entries-table'
import type { CITrustConfig } from '../types'
import type { ApiScopeTarget } from '@/features/scope/api/scope-api.types'

const mockSave = vi.fn()
let perms: string[] = []

vi.mock('../api/use-ci', () => ({
  useSaveTrustConfig: () => ({ trigger: mockSave, isMutating: false }),
}))
vi.mock('@/lib/permissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.includes(p) }) }
})
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const base: CITrustConfig = {
  id: 't1',
  name: 'acme',
  provider: 'gitlab',
  issuer: 'https://gitlab.com',
  audience: 'openctem:tenant:x',
  default_branch: 'main',
  rules: { owners: ['acme'] },
  enabled: true,
  manage_scope: true,
  scope_entries: [
    {
      pattern: 'gitlab.com/acme/*',
      scope_target_id: 's1',
      seen_at: '2026-10-15T01:00:00Z',
      seen_repository: 'gitlab.com/acme/api',
    },
    { pattern: 'gitlab.com/beta/*', scope_target_id: 's2' },
    { pattern: 'gitlab.com/gamma/*', removed_at: '2026-10-14T01:00:00Z' },
    { pattern: 'gitlab.com/delta/*' },
  ],
} as CITrustConfig

beforeEach(() => {
  mockSave.mockReset()
  perms = []
})

describe('CITrustScopeEntries', () => {
  it('lists each pattern with its evidence and links it to Scoping', () => {
    render(<CITrustScopeEntries config={base} />)
    const link = screen.getByRole('link', { name: 'gitlab.com/acme/*' })
    expect(link.getAttribute('href')).toBe('/scope?search=gitlab.com%2Facme%2F*')
    expect(screen.getByText('Seen in a verified pipeline')).toBeTruthy()
    expect(screen.getAllByText('No verified pipeline yet')).toHaveLength(3)
    // An entry a person removed stays removed, and says so.
    expect(screen.getByText(/this trust will not add it again/)).toBeTruthy()
    expect(screen.getByText(/could not be added/)).toBeTruthy()
  })

  it('names no repository when it is outside the caller data scope', () => {
    const hidden = {
      ...base,
      scope_entries: [
        { pattern: 'gitlab.com/acme/*', scope_target_id: 's1', seen_at: '2026-10-15T01:00:00Z' },
      ],
    } as CITrustConfig
    render(<CITrustScopeEntries config={hidden} />)
    const badge = screen.getByText('Seen in a verified pipeline').closest('[title]')
    expect(badge?.getAttribute('title')).toMatch(/^A verified pipeline ran under this trust on /)
  })

  it('offers adding a legacy trust to scope only to someone who may change scope', async () => {
    const legacy = { ...base, manage_scope: false, scope_entries: [] }
    perms = ['scans:ci:write']
    const { rerender } = render(<CITrustScopeEntries config={legacy} />)
    expect(screen.getByTestId('ci-trust-scope-off').textContent).toContain('not added')
    expect(screen.queryByRole('button', { name: 'Add these repositories to scope' })).toBeNull()

    perms = ['scans:ci:write', 'attack_surface:scope:write']
    const onChanged = vi.fn()
    mockSave.mockResolvedValue({})
    rerender(<CITrustScopeEntries config={legacy} onChanged={onChanged} />)
    await userEvent.click(screen.getByRole('button', { name: 'Add these repositories to scope' }))
    expect(mockSave).toHaveBeenCalledWith({ id: 't1', body: adoptScopeRequest(legacy) })
    expect(adoptScopeRequest(legacy)).toMatchObject({
      manage_scope: true,
      rules: { owners: ['acme'] },
    })
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
  })

  it('says a disabled trust adds nothing', () => {
    render(<CITrustScopeEntries config={{ ...base, enabled: false }} />)
    expect(screen.getByTestId('ci-trust-scope-off').textContent).toContain('disabled')
  })

  it('renders nothing for providers that do not manage scope', () => {
    const { container } = render(<CITrustScopeEntries config={{ ...base, provider: 'jenkins' }} />)
    expect(container.textContent).toBe('')
    expect(manageScopeSupported('github')).toBe(true)
    expect(manageScopeSupported('bitbucket')).toBe(false)
  })
})

describe('ciTrustManaged', () => {
  it('is true only for a trust-created entry a trust still links', () => {
    const managedBy = [{ trust_config_id: 't1', trust_name: 'acme' }]
    expect(ciTrustManaged({ origin: 'ci_trust', managed_by: managedBy } as ApiScopeTarget)).toBe(
      true
    )
    expect(ciTrustManaged({ origin: 'manual', managed_by: managedBy } as ApiScopeTarget)).toBe(
      false
    )
    expect(ciTrustManaged({ origin: 'ci_trust' } as ApiScopeTarget)).toBe(false)
  })
})
