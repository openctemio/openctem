import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { savePrivateDestinations, testPrivateDestination } from '../api/use-platform-settings'
import { PrivateDestinationsPanel, isWideDraft } from '../components/private-destinations-panel'
import { adminNav } from '../config/admin-nav'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { PrivateDestinationsSettings } from '../types'

vi.mock('../api/use-platform-settings', async (orig) => ({
  ...(await orig<typeof import('../api/use-platform-settings')>()),
  savePrivateDestinations: vi.fn(),
  testPrivateDestination: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))
vi.mock('../components/role-required-notice', () => ({
  RoleRequiredNotice: () => <p>role required</p>,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const settings: PrivateDestinationsSettings = {
  server_ranges: [{ cidr: '10.20.0.0/16', wide: true }],
  ranges: [{ cidr: '192.168.7.0/24', note: 'GitLab', wide: false }],
  in_force: ['192.168.7.0/24'],
  refresh_seconds: 15,
  all_private_open: false,
  signup_open: false,
  max_ranges: 32,
  version: 2,
}

beforeEach(() => {
  vi.mocked(savePrivateDestinations).mockReset().mockResolvedValue(settings)
  vi.mocked(testPrivateDestination).mockReset()
})

async function confirmWithReason(reason: string) {
  await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
  const dialog = screen.getByRole('alertdialog')
  const buttons = within(dialog).getAllByRole('button')
  const confirm = buttons[buttons.length - 1]
  expect(confirm).toBeDisabled()
  await userEvent.type(within(dialog).getByLabelText('Reason'), reason)
  await userEvent.click(confirm)
  return dialog
}

describe('private networks', () => {
  it('is listed in the console navigation', () => {
    const urls = adminNav.flatMap((g) => g.items.map((i) => i.url))
    expect(urls).toContain('/system/private-networks')
  })

  it('shows the server ranges read only beside the console ranges', () => {
    render(<PrivateDestinationsPanel settings={settings} canEdit onSaved={() => {}} />)
    expect(screen.getByTestId('server-ranges')).toHaveTextContent('10.20.0.0/16')
    expect(screen.getByDisplayValue('192.168.7.0/24')).toBeInTheDocument()
    expect(screen.getByDisplayValue('GitLab')).toBeInTheDocument()
  })

  it('adds a range and saves it with the version and a reason', async () => {
    render(<PrivateDestinationsPanel settings={settings} canEdit onSaved={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: 'Add range' }))
    const inputs = screen.getAllByLabelText('Range')
    await userEvent.type(inputs[inputs.length - 1], '10.30.0.0/16')
    expect(screen.getByText(/A wide range/)).toBeInTheDocument()
    await confirmWithReason('mail relay')
    expect(savePrivateDestinations).toHaveBeenCalledWith({
      ranges: [
        { cidr: '192.168.7.0/24', note: 'GitLab' },
        { cidr: '10.30.0.0/16', note: undefined },
      ],
      reason: 'mail relay',
      version: 2,
    })
  })

  it('shows a refused range under its row', async () => {
    vi.mocked(savePrivateDestinations).mockRejectedValue(
      new AdminApiError('refused', 400, 'PRIVATE_RANGE_INVALID', {
        index: 0,
        range: '192.168.7.0/24',
        reason: 'not_private',
      })
    )
    render(<PrivateDestinationsPanel settings={settings} canEdit onSaved={() => {}} />)
    await userEvent.type(screen.getByDisplayValue('GitLab'), ' 2')
    await confirmWithReason('try')
    expect((await screen.findAllByText(/Only ranges inside 10.0.0.0\/8/)).length).toBeGreaterThan(0)
  })

  it('without the permission shows the list but no editing or test', () => {
    render(<PrivateDestinationsPanel settings={settings} canEdit={false} onSaved={() => {}} />)
    expect(screen.getByDisplayValue('192.168.7.0/24')).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Add range' })).toBeNull()
    expect(screen.queryByLabelText('Host name')).toBeNull()
  })

  it('tests a destination and offers the range that would open a blocked address', async () => {
    vi.mocked(testPrivateDestination).mockResolvedValue({
      host: 'gitlab.example.com',
      name_blocked: false,
      addresses: [
        { address: '10.30.1.9', verdict: 'blocked_private', suggested: '10.30.1.0/24' },
        { address: '169.254.169.254', verdict: 'hard_blocked', hard_block: 'link_local' },
      ],
    })
    render(<PrivateDestinationsPanel settings={settings} canEdit onSaved={() => {}} />)
    await userEvent.type(screen.getByLabelText('Host name'), 'gitlab.example.com')
    await userEvent.click(screen.getByRole('button', { name: 'Test' }))
    expect(testPrivateDestination).toHaveBeenCalledWith('gitlab.example.com')
    const result = await screen.findByTestId('destination-result')
    expect(result).toHaveTextContent('Never reachable')
    await userEvent.click(within(result).getByRole('button', { name: 'Add 10.30.1.0/24' }))
    expect(screen.getByDisplayValue('10.30.1.0/24')).toBeInTheDocument()
  })

  it('flags wide drafts only', () => {
    expect(isWideDraft('10.0.0.0/8')).toBe(true)
    expect(isWideDraft('10.1.1.0/24')).toBe(false)
    expect(isWideDraft('fd12::/48')).toBe(true)
    expect(isWideDraft('fd12:0:0:1::/64')).toBe(false)
    expect(isWideDraft('nonsense')).toBe(false)
  })
})
