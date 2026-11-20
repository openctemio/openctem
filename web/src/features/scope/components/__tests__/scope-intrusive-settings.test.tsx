/**
 * The owner-only T2 duration (RFC-054 §12.4): only an owner changes it, with
 * a reason; the add and edit dialogs bound a T2 entry by it.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const role = vi.hoisted(() => ({ owner: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: () => true,
    usePermissions: () => ({ can: () => true, isOwner: () => role.owner }),
    Can: ({ children }: { children: ReactNode }) => <>{children}</>,
  }
})
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

// Radix Select uses pointer capture and scrollIntoView, which jsdom lacks.
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}
Element.prototype.scrollIntoView ??= () => {}

const { ScopeIntrusiveSettings } = await import('../scope-intrusive-settings')
const { expiryBoundFor } = await import('../../lib/scope-entry')

const settings = { t2_max_duration: '30d' as const, t2_max_days: 30, t2_permanent_allowed: false }

beforeEach(() => {
  api.put.mockReset()
  role.owner = true
})

describe('expiryBoundFor', () => {
  it('bounds T2 by the owner limit and other tiers by the one-off limit', () => {
    const s = { one_off_max_days: 7, t2_max_days: 90, t2_permanent_allowed: false }
    expect(expiryBoundFor('t2', s)).toEqual({ maxDays: 90, permanent: false })
    expect(expiryBoundFor('t1', s)).toEqual({ maxDays: 7, permanent: true })
    expect(expiryBoundFor('t2', { ...s, t2_permanent_allowed: true }).permanent).toBe(true)
    expect(expiryBoundFor('t2', undefined)).toEqual({ maxDays: 30, permanent: false })
  })
})

describe('Intrusive (T2) entries setting', () => {
  it('is read-only for someone who is not an owner', () => {
    role.owner = false
    render(<ScopeIntrusiveSettings settings={settings} />)
    expect(screen.getByText('Set by an owner of your organization.')).toBeInTheDocument()
    expect(screen.getByTestId('t2-max-duration')).toHaveTextContent('30 days (default)')
    expect(screen.getByTestId('t2-attestation-days')).toHaveTextContent('90 days')
    expect(screen.queryByRole('button', { name: 'Change' })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
  })

  it('an owner saves a new limit with a reason in the dialog', async () => {
    api.put.mockResolvedValue({ ...settings, t2_max_duration: 'permanent' })
    const onSaved = vi.fn()
    const user = userEvent.setup()
    render(<ScopeIntrusiveSettings settings={settings} onSaved={onSaved} />)
    await user.click(screen.getByRole('button', { name: 'Change' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('combobox', { name: 'Longest intrusive entry' }))
    await user.click(await screen.findByRole('option', { name: 'Permanent' }))
    const save = within(dialog).getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled() // a reason first
    await user.type(within(dialog).getByLabelText('Reason'), 'standing contract')
    await user.click(save)
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/scope/settings/intrusive', {
        t2_max_duration: 'permanent',
        t2_attestation_days: 90,
        reason: 'standing contract',
      })
    )
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('keeps the dialog open with the reason when the save fails', async () => {
    api.put.mockRejectedValue(new Error('step-up refused'))
    const user = userEvent.setup()
    render(<ScopeIntrusiveSettings settings={settings} />)
    await user.click(screen.getByRole('button', { name: 'Change' }))
    const dialog = await screen.findByRole('dialog')
    await user.clear(within(dialog).getByRole('spinbutton'))
    await user.type(within(dialog).getByRole('spinbutton'), '120')
    await user.type(within(dialog).getByLabelText('Reason'), 'audit cycle')
    await user.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(await within(dialog).findByRole('alert')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('Reason')).toHaveValue('audit cycle')
  })
})
