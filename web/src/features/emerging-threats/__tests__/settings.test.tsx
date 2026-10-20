import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { EmergingThreatsSettingsForm } from '../components/settings-form'
import { validateSettings, type EmergingThreatsSettings } from '../types'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => '/settings/emerging-threats',
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const base: EmergingThreatsSettings = {
  disabled: false,
  immediate_threshold: 75,
  digest_threshold: 40,
  digest_hour: 8,
  quiet_hours: { enabled: false, start_hour: 22, end_hour: 7 },
  quiet_override: 90,
  include_possible_in_immediate: false,
  asset_names_in_messages: false,
}

describe('validateSettings', () => {
  it('accepts the defaults', () => {
    expect(validateSettings(base)).toEqual({})
  })
  it.each([
    ['immediate_threshold', { immediate_threshold: 59 }],
    ['immediate_threshold', { immediate_threshold: 91 }],
    ['digest_threshold', { digest_threshold: 19 }],
    ['digest_threshold', { digest_threshold: 61 }],
    ['digest_hour', { digest_hour: 24 }],
    ['digest_hour', { digest_hour: -1 }],
    ['quiet_override', { quiet_override: 69 }],
    ['quiet_override', { quiet_override: 101 }],
    ['immediate_threshold', { immediate_threshold: NaN }],
    ['digest_threshold', { digest_threshold: 60, immediate_threshold: 60 }],
  ])('rejects %s out of bounds', (field, patch) => {
    expect(validateSettings({ ...base, ...patch })[field]).toBeTruthy()
  })
  it('checks quiet hours only when enabled', () => {
    const off = { ...base, quiet_hours: { enabled: false, start_hour: 99, end_hour: 99 } }
    expect(validateSettings(off)).toEqual({})
    const on = { ...base, quiet_hours: { enabled: true, start_hour: 24, end_hour: 7 } }
    expect(validateSettings(on).quiet_start).toBeTruthy()
    const same = { ...base, quiet_hours: { enabled: true, start_hour: 5, end_hour: 5 } }
    expect(validateSettings(same).quiet_end).toBeTruthy()
  })
})

const renderForm = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <EmergingThreatsSettingsForm initial={base} timezone="Asia/Ho_Chi_Minh" formId="f" />
    </SWRConfig>
  )

beforeEach(() => {
  api.put.mockReset()
})

describe('EmergingThreatsSettingsForm', () => {
  it('shows the digest hour as HH:00 in the organization time zone', () => {
    renderForm()
    expect(screen.getByText('The digest goes out at 08:00 (Asia/Ho_Chi_Minh).')).toBeInTheDocument()
  })

  it('does not save a value out of bounds', async () => {
    renderForm()
    const input = screen.getByLabelText('Immediate threshold')
    await userEvent.clear(input)
    await userEvent.type(input, '50')
    await userEvent.click(screen.getByRole('button', { name: /Save/ }))
    expect(await screen.findByText('Enter a whole number from 60 to 90.')).toBeInTheDocument()
    expect(api.put).not.toHaveBeenCalled()
  })

  it('saves with the enabled switch stored inverted', async () => {
    api.put.mockImplementation(async (_u: string, body: EmergingThreatsSettings) => body)
    renderForm()
    await userEvent.click(screen.getByRole('switch', { name: 'Emerging-threat alerts' }))
    await userEvent.click(screen.getByRole('switch', { name: 'Name assets in messages' }))
    await userEvent.click(screen.getByRole('button', { name: /Save/ }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/organization/settings/emerging-threats', {
        ...base,
        disabled: true,
        asset_names_in_messages: true,
      })
    )
  })
})
