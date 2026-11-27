/**
 * /settings/scope in the settings page frame: loading, a failed load with
 * Retry (never defaults shown as saved), the view-only notice without
 * scope:approve, and the form when the policy is loaded.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => '/settings/scope',
  useSearchParams: () => new URLSearchParams(),
}))

const mutate = vi.fn()
const state: { data?: unknown; error?: unknown; isLoading: boolean } = { isLoading: false }
vi.mock('@/features/scope', () => ({
  useScopeSettingsApi: () => ({ ...state, mutate }),
}))
vi.mock('@/features/scope/components/scope-settings-form', () => ({
  ScopeSettingsForm: () => <div data-testid="scope-form" />,
}))
const perms = vi.hoisted(() => ({ approve: true }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => perms.approve,
}))

const { default: ScopeSettingsPage } = await import('../page')

beforeEach(() => {
  state.data = undefined
  state.error = undefined
  state.isLoading = false
  perms.approve = true
  mutate.mockReset()
})

describe('/settings/scope', () => {
  it('shows the frame with loading rows while the policy loads', () => {
    state.isLoading = true
    render(<ScopeSettingsPage />)
    expect(screen.getByRole('heading', { level: 1, name: 'Scope policy' })).toBeInTheDocument()
    expect(screen.getByLabelText('Loading Scope policy')).toBeInTheDocument()
    expect(screen.queryByTestId('scope-form')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Scope entries' })).toHaveAttribute('href', '/scope')
  })

  it('says the load failed and retries, never showing the form', async () => {
    state.error = new Error('down')
    render(<ScopeSettingsPage />)
    expect(screen.getByText("Couldn't load Scope policy")).toBeInTheDocument()
    expect(screen.queryByTestId('scope-form')).not.toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }))
    expect(mutate).toHaveBeenCalled()
  })

  it('shows the form, and the view-only notice without scope:approve', () => {
    state.data = { one_off_targets: 'admins' }
    perms.approve = false
    render(<ScopeSettingsPage />)
    expect(screen.getByTestId('scope-form')).toBeInTheDocument()
    expect(
      screen.getByText('View only. Only scope approvers can change these settings.')
    ).toBeInTheDocument()
  })

  it('shows no view-only notice to a scope approver', () => {
    state.data = { one_off_targets: 'admins' }
    render(<ScopeSettingsPage />)
    expect(screen.queryByText(/View only/)).not.toBeInTheDocument()
  })
})
