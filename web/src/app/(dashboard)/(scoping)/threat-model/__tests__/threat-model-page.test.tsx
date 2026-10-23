import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ThreatModelPage from '../page'

const mutateModel = vi.fn()
const mutateModels = vi.fn()
let detail: { model?: unknown; isLoading: boolean; error?: unknown } = { isLoading: false }
let list: { models: unknown[]; isLoading: boolean; error?: unknown } = {
  models: [],
  isLoading: false,
}

vi.mock('@/features/threat-model', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/features/threat-model')>()),
  useThreatModels: () => ({ ...list, mutate: mutateModels }),
  useThreatModel: () => ({ ...detail, mutate: mutateModel }),
  useCrownJewels: () => ({ crownJewels: [], isLoading: false }),
  useAttackerProfileMap: () => ({ profileMap: new Map(), isLoading: false }),
  useAssetNameMap: () => ({ nameFor: () => '' }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/shared/components/gated-section-tabs', () => ({
  GatedSectionTabs: () => <nav aria-label="Threat model sections" />,
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => children,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('threat model page', () => {
  beforeEach(() => {
    mutateModel.mockClear()
    mutateModels.mockClear()
    detail = { isLoading: false }
    list = { models: [], isLoading: false }
    window.history.replaceState(null, '', '/threat-model')
  })

  it('shows an error with retry and the section tabs for a bad ?model= id, not a skeleton forever', async () => {
    window.history.replaceState(null, '', '/threat-model?model=gone')
    detail = { isLoading: false, error: new Error('not found') }
    render(<ThreatModelPage />)
    expect(screen.getByRole('navigation', { name: 'Threat model sections' })).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    expect(mutateModel).toHaveBeenCalled()
    expect(screen.getByRole('button', { name: /all models/i })).toBeInTheDocument()
  })

  it('shows an error with retry when the models list fails, not "No threat models yet"', async () => {
    list = { models: [], isLoading: false, error: new Error('boom') }
    render(<ThreatModelPage />)
    expect(screen.queryByText(/no threat models yet/i)).toBeNull()
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    expect(mutateModels).toHaveBeenCalled()
  })
})
