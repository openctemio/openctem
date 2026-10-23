import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import CrownJewelsPage from '../page'

const reload = vi.fn()
let hookState: { data?: unknown; error?: unknown; isLoading: boolean } = { isLoading: false }
const allAssetsCalls: Array<[string | undefined, boolean | undefined]> = []

vi.mock('@/features/crown-jewels/api/use-crown-jewels', () => ({
  useCrownJewels: () => ({ ...hookState, mutate: reload }),
  useAllAssets: (search?: string, enabled?: boolean) => {
    allAssetsCalls.push([search, enabled])
    return { data: undefined }
  },
  useDesignateCrownJewel: () => ({ trigger: vi.fn(), isMutating: false }),
  useUndesignateCrownJewel: () => ({ trigger: vi.fn(), isMutating: false }),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: () => canWrite,
  Can: ({ children, permission }: { children: React.ReactNode; permission: string }) =>
    permission === 'assets:write' && !canWrite ? null : children,
}))
vi.mock('@/features/shared/components/gated-section-tabs', () => ({ GatedSectionTabs: () => null }))
vi.mock('@/context/risk-scoring-provider', () => ({
  useRiskThresholds: () => ({ critical: 90, high: 70, medium: 40, low: 10 }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

let canWrite = true

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const asset = {
  id: 'a1',
  name: 'Payments DB',
  type: 'database',
  risk_score: 80,
  properties: { business_impact_score: 90, business_impact_notes: 'Card data lives here' },
}

describe('crown jewels page', () => {
  beforeEach(() => {
    canWrite = true
    hookState = { data: { data: [asset], total: 1 }, isLoading: false }
    allAssetsCalls.length = 0
    reload.mockClear()
  })

  it('opens the edit form with the stored business impact notes', async () => {
    const user = userEvent.setup()
    render(<CrownJewelsPage />)
    await user.click(screen.getByRole('button', { name: /open row actions/i }))
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText(/business impact notes/i)).toHaveValue(
      'Card data lives here'
    )
  })

  it('shows the stored notes in the sheet and has no Dependencies tab', async () => {
    const user = userEvent.setup()
    render(<CrownJewelsPage />)
    await user.click(screen.getByText('Payments DB'))
    const sheet = await screen.findByRole('dialog')
    expect(within(sheet).getByText('Card data lives here')).toBeInTheDocument()
    expect(within(sheet).queryByText(/dependencies/i)).toBeNull()
  })

  it('readers keep View details in the row menu', async () => {
    canWrite = false
    const user = userEvent.setup()
    render(<CrownJewelsPage />)
    await user.click(screen.getByRole('button', { name: /open row actions/i }))
    expect(await screen.findByRole('menuitem', { name: 'View details' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Edit' })).toBeNull()
  })

  it('shows an error with retry instead of the empty state when the load fails', async () => {
    hookState = { error: new Error('boom'), isLoading: false }
    const user = userEvent.setup()
    render(<CrownJewelsPage />)
    expect(screen.queryByText('No crown jewels yet')).toBeNull()
    await user.click(screen.getByRole('button', { name: /retry/i }))
    expect(reload).toHaveBeenCalled()
  })

  it('keeps the designate picker idle until the dialog opens', async () => {
    const user = userEvent.setup()
    render(<CrownJewelsPage />)
    expect(allAssetsCalls.every(([, enabled]) => enabled === false)).toBe(true)
    await user.click(screen.getByRole('button', { name: /designate crown jewel/i }))
    expect(allAssetsCalls.at(-1)?.[1]).toBe(true)
  })
})
