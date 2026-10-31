import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { saveEmailRelay, saveMFAFloor } from '../api/use-platform-settings'
import { MFAFloorForm, graceDays } from '../components/mfa-floor-form'
import { EmailRelayForm } from '../components/email-relay-form'
import { adminNav } from '../config/admin-nav'
import type { EmailRelaySettings, MFAFloorSettings } from '../types'

vi.mock('../api/use-platform-settings', async (orig) => ({
  ...(await orig<typeof import('../api/use-platform-settings')>()),
  saveMFAFloor: vi.fn(),
  saveEmailRelay: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const floor: MFAFloorSettings = {
  floor: 'admins',
  source: 'console',
  default: 'admins',
  env_var: 'AUTH_MFA_FLOOR',
  grace_days_existing: 14,
  grace_days_new: 7,
  effective_from: '2026-10-01T00:00:00Z',
  recommend_raise: false,
  version: 3,
  changed_at: '2026-10-18T09:00:00Z',
  changed_by: 'root@example.test',
}

const relay: EmailRelaySettings = {
  mode: 'verified_sender',
  source: 'default',
  default: 'verified_sender',
  env_var: 'ORG_EMAIL_RELAY_MODE',
  version: 1,
}

beforeEach(() => {
  vi.mocked(saveMFAFloor).mockReset().mockResolvedValue(floor)
  vi.mocked(saveEmailRelay).mockReset().mockResolvedValue(relay)
})

async function confirmWithReason(reason: string) {
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  const dialog = screen.getByRole('alertdialog')
  const buttons = within(dialog).getAllByRole('button')
  const confirm = buttons[buttons.length - 1]
  expect(confirm).toBeDisabled()
  await userEvent.type(within(dialog).getByLabelText('Reason'), reason)
  await userEvent.click(confirm)
  return dialog
}

describe('two-factor floor', () => {
  it('raises the floor with grace days, the version and a reason', async () => {
    render(<MFAFloorForm settings={floor} canEdit onSaved={() => {}} />)
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await userEvent.click(screen.getByLabelText('Everyone'))
    await userEvent.clear(screen.getByLabelText('Current members'))
    await userEvent.type(screen.getByLabelText('Current members'), '30')
    const dialog = await confirmWithReason('audit finding 12')
    expect(dialog).toHaveTextContent('Change the two-factor floor?')
    await waitFor(() =>
      expect(saveMFAFloor).toHaveBeenCalledWith({
        floor: 'everyone',
        grace_days_existing: 30,
        grace_days_new: 7,
        reason: 'audit finding 12',
        version: 3,
      })
    )
  })

  it('warns before lowering it', async () => {
    render(<MFAFloorForm settings={floor} canEdit onSaved={() => {}} />)
    await userEvent.click(screen.getByLabelText('No floor'))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(screen.getByRole('alertdialog')).toHaveTextContent('Lower the two-factor floor?')
  })

  it('refuses grace days outside 0 to 90', async () => {
    expect(graceDays('0')).toBe(0)
    expect(graceDays('90')).toBe(90)
    expect(graceDays('91')).toBeNull()
    expect(graceDays('-1')).toBeNull()
    expect(graceDays('7.5')).toBeNull()
    render(<MFAFloorForm settings={floor} canEdit onSaved={() => {}} />)
    await userEvent.clear(screen.getByLabelText('New members'))
    await userEvent.type(screen.getByLabelText('New members'), '120')
    expect(screen.getByText('Enter a whole number of days from 0 to 90.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('recommends a floor on an install still on none, and is read-only without the permission', () => {
    render(
      <MFAFloorForm
        settings={{ ...floor, floor: 'none', recommend_raise: true }}
        canEdit={false}
        onSaved={() => {}}
      />
    )
    expect(screen.getByTestId('mfa-floor-recommend')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Everyone')).toBeDisabled()
  })

  it('is listed under Settings in the console navigation', () => {
    const settings = adminNav.find((s) => s.title === 'Settings')!.items.map((i) => i.url)
    expect(settings).toContain('/system/two-factor')
  })
})

describe('organization mail servers', () => {
  it('changes the mode with the version and a reason', async () => {
    render(<EmailRelayForm settings={relay} canEdit onSaved={() => {}} />)
    expect(screen.getByText('Server default (ORG_EMAIL_RELAY_MODE).')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await userEvent.click(screen.getByLabelText('Never'))
    await confirmWithReason('free plan')
    await waitFor(() =>
      expect(saveEmailRelay).toHaveBeenCalledWith({ mode: 'off', reason: 'free plan', version: 1 })
    )
  })

  it('is read-only without the permission', () => {
    render(<EmailRelayForm settings={relay} canEdit={false} onSaved={() => {}} />)
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Never')).toBeDisabled()
  })
})
