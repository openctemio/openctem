import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { AssetAttribution } from '../../lib/attribution'

const state = vi.hoisted(() => ({
  attribution: undefined as AssetAttribution | undefined,
  decide: vi.fn(),
  mutate: vi.fn(),
  perms: [] as string[],
}))

vi.mock('../../hooks/use-asset-attribution', () => ({
  useAssetAttribution: () => ({
    attribution: state.attribution,
    isLoading: false,
    mutate: state.mutate,
  }),
  useDecideAttribution: () => ({ decide: state.decide, saving: false }),
}))

vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => state.perms.includes(p) }) }
})

// The dialogs have their own tests; here only whether they are offered.
vi.mock('../inventory/mark-out-of-scope-action', () => ({
  MarkOutOfScopeAction: () => <button type="button">Mark out of scope</button>,
}))
vi.mock('@/features/scope/components/scope-entry-dialog', () => ({
  ScopeEntryDialog: ({ open }: { open: boolean }) => (open ? <div role="dialog">entry</div> : null),
}))
vi.mock('@/features/scans/components/scan-assets-dialog', () => ({
  ScanAssetsDialog: ({ open }: { open: boolean }) => (open ? <div role="dialog">scan</div> : null),
}))

import { AssetScanningSection } from '../asset-scanning-section'

const SUBDOMAIN = { id: 'a1', name: 'portal.example.com', type: 'subdomain' as const }
const ALL = ['attack_surface:scope:write', 'assets:write', 'scans:write', 'scans:execute']

function attribution(overrides: Partial<AssetAttribution>): AssetAttribution {
  return {
    state: 'discovered',
    confidence: 80,
    recorded: true,
    human_decided: false,
    active_checks_allowed: true,
    evidence: [],
    scope_status: 'in_scope',
    covered_by: { kind: 'scope_target', pattern: '*.example.com' },
    ...overrides,
  }
}

beforeEach(() => {
  state.attribution = undefined
  state.perms = []
  state.decide.mockReset()
  state.mutate.mockReset()
})

describe('AssetScanningSection', () => {
  it('in scope: says what covers it and offers Scan now', () => {
    state.attribution = attribution({})
    state.perms = ALL
    render(<AssetScanningSection asset={SUBDOMAIN} />)
    expect(screen.getByText('In scope through the scope entry *.example.com.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add to scope' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('scan')
  })

  it('discovered and uncovered: passive only, Add to scope and Mark out of scope, no Scan now', () => {
    state.attribution = attribution({
      active_checks_allowed: false,
      active_checks_blocked_by: 'discovered',
      blocked_code: 'no_entry',
      scope_status: 'out_of_scope',
      covered_by: undefined,
    })
    state.perms = ALL
    render(<AssetScanningSection asset={SUBDOMAIN} />)
    expect(screen.getByText(/passive only/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add to scope' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Mark out of scope' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Scan now' })).not.toBeInTheDocument()
  })

  it('wildcard-only: a person confirms, then scans may reach it', async () => {
    state.attribution = attribution({
      active_checks_allowed: false,
      active_checks_blocked_by: 'wildcard_only',
      blocked_code: 'wildcard_only',
    })
    state.perms = ALL
    state.decide.mockResolvedValue(attribution({ state: 'confirmed' }))
    render(<AssetScanningSection asset={SUBDOMAIN} />)
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and allow scanning' }))
    await waitFor(() => expect(state.decide).toHaveBeenCalledWith('confirmed'))
  })

  it('offers no action without the permissions (the API stays the authority)', () => {
    state.attribution = attribution({
      active_checks_allowed: false,
      blocked_code: 'wildcard_only',
      scope_status: 'out_of_scope',
      covered_by: undefined,
    })
    state.perms = ['assets:read']
    render(<AssetScanningSection asset={SUBDOMAIN} />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('scans:write alone is not enough to scan (scans:execute too)', () => {
    state.attribution = attribution({})
    state.perms = ['scans:write']
    render(<AssetScanningSection asset={SUBDOMAIN} />)
    expect(screen.queryByRole('button', { name: 'Scan now' })).not.toBeInTheDocument()
  })

  it('an excluded or rejected asset is not offered Mark out of scope again', () => {
    state.attribution = attribution({ active_checks_allowed: false, blocked_code: 'excluded' })
    state.perms = ALL
    const { rerender } = render(<AssetScanningSection asset={SUBDOMAIN} />)
    expect(screen.queryByRole('button', { name: 'Mark out of scope' })).not.toBeInTheDocument()
    state.attribution = attribution({ state: 'rejected', active_checks_allowed: false })
    rerender(<AssetScanningSection asset={SUBDOMAIN} />)
    expect(screen.queryByRole('button', { name: 'Mark out of scope' })).not.toBeInTheDocument()
  })

  it('a type without a scan target (repository) gets no Scan now', () => {
    state.attribution = attribution({ scope_status: 'not_applicable' })
    state.perms = ALL
    render(
      <AssetScanningSection
        asset={{ id: 'r1', name: 'github.com/x/y', type: 'repository' as const }}
      />
    )
    expect(screen.queryByRole('button', { name: 'Scan now' })).not.toBeInTheDocument()
  })

  it('renders nothing without an answer', () => {
    const { container } = render(<AssetScanningSection asset={SUBDOMAIN} />)
    expect(container).toBeEmptyDOMElement()
  })
})
