/**
 * research/245 area B, /attack-surface/external: the Expiring certificates
 * tile needs both read permissions and shows a dash on error; create and
 * edit have a busy state; a cleared field is sent as an explicit null; the
 * dialog is translated and its Type label is bound to its control.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const push = vi.hoisted(() => vi.fn())
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push }),
  usePathname: () => '/attack-surface/external',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
const perms = vi.hoisted(() => ({ exposures: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({
      can: (p: string) => p !== actual.Permission.ExposuresRead || perms.exposures,
    }),
    Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  }
})

const asset = {
  id: '0198f0e2-1111-7000-8000-000000000001',
  name: 'api.example.com',
  type: 'subdomain',
  riskScore: 50,
  findingCount: 0,
  tags: [],
  lastSeen: '2026-10-01T00:00:00Z',
  description: 'notes',
  metadata: { ip_addresses: ['203.0.113.10'], port: 443, parent_domain: 'example.com' },
}
const assets = vi.hoisted(() => ({
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  exposures: { total: 3, error: undefined as unknown },
}))
vi.mock('@/features/assets', () => ({
  createAsset: assets.createAsset,
  updateAsset: assets.updateAsset,
  useAssets: () => ({
    assets: [asset],
    total: 1,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
}))
vi.mock('@/features/assets/hooks/use-assets', () => ({ fetchAllAssets: vi.fn() }))
vi.mock('@/features/assets/components/service-cells', () => ({
  IssuesChip: () => null,
  LabelChips: () => null,
  SurfaceFacts: () => null,
}))
vi.mock('@/features/assets/components/asset-delete-dialog-shared', () => ({
  AssetDeleteDialogShared: () => null,
}))
vi.mock('@/features/exposures/hooks', () => ({
  useExposures: () => ({ total: assets.exposures.total, error: assets.exposures.error }),
}))
vi.mock('@/features/scans/components', () => ({ ScanAssetsDialog: () => null }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('@/context/risk-scoring-provider', () => ({
  useRiskThresholds: () => ({ critical_min: 80, high_min: 60, medium_min: 40, low_min: 10 }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))

const { default: Page } = await import('@/app/(dashboard)/(scoping)/attack-surface/external/page')

beforeEach(() => {
  push.mockReset()
  assets.createAsset.mockReset()
  assets.updateAsset.mockReset().mockResolvedValue({})
  assets.exposures.total = 3
  assets.exposures.error = undefined
  perms.exposures = true
  window.history.replaceState(null, '', '/attack-surface/external')
})

describe('external attack surface', () => {
  it('the certificates tile opens the exposures list', async () => {
    render(<Page />)
    expect(screen.getByRole('link', { name: /Expiring certificates/ })).toHaveAttribute(
      'href',
      '/exposures?q=certificate'
    )
  })

  it('the certificates tile shows a dash, never a false 0, without exposures:read or on error', () => {
    perms.exposures = false
    const { unmount } = render(<Page />)
    const tile = screen.getByText('Expiring certificates').closest('button, div') as HTMLElement
    expect(tile.parentElement).toHaveTextContent('—')
    expect(screen.getByText('Needs permission to read exposures')).toBeInTheDocument()
    unmount()
    perms.exposures = true
    assets.exposures.error = new Error('boom')
    render(<Page />)
    expect(screen.getByText('Could not be loaded')).toBeInTheDocument()
  })

  it('the Add dialog binds the Type label and submits once while busy', async () => {
    let resolve!: (v: unknown) => void
    assets.createAsset.mockReturnValue(new Promise((r) => (resolve = r)))
    render(<Page />)
    await userEvent.click(screen.getByRole('button', { name: 'Add asset' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText('Type')).toBeInTheDocument()
    await userEvent.type(within(dialog).getByLabelText('Name'), 'new.example.com')
    const add = within(dialog).getByRole('button', { name: 'Add asset' })
    await userEvent.click(add)
    await userEvent.click(add)
    expect(assets.createAsset).toHaveBeenCalledTimes(1)
    expect(add).toBeDisabled()
    resolve({})
  })

  it('editing sends an explicit null for a cleared address, port and parent, and clears the notes', async () => {
    render(<Page />)
    await userEvent.click(screen.getByRole('button', { name: /open menu|actions/i }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Edit' }))
    const dialog = await screen.findByRole('dialog')
    for (const label of ['Parent domain', 'IP address', 'Port', 'Notes']) {
      await userEvent.clear(within(dialog).getByLabelText(label))
    }
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(assets.updateAsset).toHaveBeenCalledTimes(1))
    const [, input] = assets.updateAsset.mock.calls[0]
    expect(input.metadata).toEqual({ ip_addresses: null, port: null, parent_domain: null })
    expect(input.description).toBe('')
  })
})
