import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({
  useProgramDelivery: vi.fn(),
  useNotificationChannelOptions: vi.fn(),
  attachProgramChannel: vi.fn(),
  detachProgramChannel: vi.fn(),
  setProgramOrgChannels: vi.fn(),
}))
vi.mock('../../api/use-programs', () => api)
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback: string, vars?: Record<string, unknown>) =>
      fallback.replace(/\{(\w+)\}/g, (_m, v: string) => String(vars?.[v] ?? '')),
  }),
}))

import { toast } from 'sonner'
import { ApiClientError } from '@/lib/api/error-handler'
import { ProgramNotifications } from '../program-notifications'
import type { Program, ProgramDelivery } from '../../api/programs-api.types'

function program(over: Partial<Program> = {}): Program {
  return {
    id: 'p1',
    name: 'Acme',
    platform: 'self',
    handle: 'acme',
    program_url: '',
    visibility: 'private',
    terms_text: '',
    locked: false,
    status: 'active',
    scope_source: 'paste',
    authoritative: true,
    rules: {},
    max_tier: 't1',
    terms_sha256: 'a'.repeat(64),
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    ...over,
  }
}

// Radix Select needs these in jsdom.
Element.prototype.scrollIntoView = vi.fn()
Element.prototype.releasePointerCapture = vi.fn()

const mutate = vi.fn()

function setDelivery(d: Partial<ProgramDelivery> = {}) {
  api.useProgramDelivery.mockReturnValue({
    data: {
      program_id: 'p1',
      org_channels: false,
      channels: [{ integration_id: 'i-slack', name: 'Team Slack', provider: 'slack' }],
      ...d,
    },
    error: undefined,
    mutate,
  })
}

describe('ProgramNotifications', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setDelivery()
    api.useNotificationChannelOptions.mockReturnValue({
      data: [
        { id: 'i-slack', name: 'Team Slack', provider: 'slack' },
        { id: 'i-hook', name: 'SOC webhook', provider: 'webhook' },
      ],
    })
  })

  it('renders nothing for a public program and never loads its delivery', () => {
    const { container } = render(
      <ProgramNotifications program={program({ visibility: 'public' })} canManage isOwner />
    )
    expect(container).toBeEmptyDOMElement()
    expect(api.useProgramDelivery).toHaveBeenCalledWith(null)
    expect(api.useNotificationChannelOptions).toHaveBeenCalledWith(false)
  })

  it('explains the default and lists the attached channels', () => {
    render(<ProgramNotifications program={program()} canManage isOwner={false} />)
    expect(
      screen.getByText(/do not go to organization-wide channels by default/)
    ).toBeInTheDocument()
    expect(screen.getByText('Team Slack')).toBeInTheDocument()
  })

  it('without manage permissions: read-only list, no attach or detach, no options fetch', () => {
    render(<ProgramNotifications program={program()} canManage={false} isOwner={false} />)
    expect(screen.queryByRole('button', { name: /Attach channel/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Detach Team Slack/ })).toBeNull()
    expect(screen.getByText(/needs permission to edit programs/)).toBeInTheDocument()
    expect(api.useNotificationChannelOptions).toHaveBeenCalledWith(false)
  })

  it('offers only channels not yet attached and attaches the chosen one', async () => {
    api.attachProgramChannel.mockResolvedValue({})
    render(<ProgramNotifications program={program()} canManage isOwner={false} />)
    await userEvent.click(screen.getByRole('combobox', { name: /Choose a notification channel/ }))
    const listbox = await screen.findByRole('listbox')
    expect(within(listbox).queryByText(/Team Slack/)).toBeNull()
    await userEvent.click(within(listbox).getByText(/SOC webhook/))
    await userEvent.click(screen.getByRole('button', { name: /Attach channel/ }))
    await waitFor(() => expect(api.attachProgramChannel).toHaveBeenCalledWith('p1', 'i-hook'))
    expect(mutate).toHaveBeenCalled()
    expect(toast.success).toHaveBeenCalledWith('Channel attached')
  })

  it('detaches only after confirmation', async () => {
    api.detachProgramChannel.mockResolvedValue({})
    render(<ProgramNotifications program={program()} canManage isOwner={false} />)
    await userEvent.click(screen.getByRole('button', { name: 'Detach Team Slack' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(api.detachProgramChannel).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Detach' }))
    await waitFor(() => expect(api.detachProgramChannel).toHaveBeenCalledWith('p1', 'i-slack'))
  })

  it('cancelling the detach confirmation changes nothing', async () => {
    render(<ProgramNotifications program={program()} canManage isOwner={false} />)
    await userEvent.click(screen.getByRole('button', { name: 'Detach Team Slack' }))
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(api.detachProgramChannel).not.toHaveBeenCalled()
  })

  it('a non-owner sees the organization toggle disabled, with the reason', () => {
    render(<ProgramNotifications program={program()} canManage isOwner={false} />)
    expect(
      screen.getByRole('switch', { name: /Also send to organization channels/ })
    ).toBeDisabled()
    expect(screen.getByText(/Only an organization owner can change this/)).toBeInTheDocument()
  })

  it('an owner opts in only with a 10 to 500 character reason, through the confirm dialog', async () => {
    api.setProgramOrgChannels.mockResolvedValue({})
    render(<ProgramNotifications program={program()} canManage={false} isOwner />)
    await userEvent.click(
      screen.getByRole('switch', { name: /Also send to organization channels/ })
    )
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText(/You will be asked to sign in again/)).toBeInTheDocument()
    const confirm = within(dialog).getByRole('button', { name: 'Send to organization channels' })
    expect(confirm).toBeDisabled()
    const reason = within(dialog).getByLabelText(/Reason/)
    await userEvent.type(reason, 'too short')
    expect(confirm).toBeDisabled()
    await userEvent.type(reason, ' - SOC triage rota covers this program')
    expect(confirm).toBeEnabled()
    expect(reason).toHaveAttribute('maxLength', '500')
    await userEvent.click(confirm)
    await waitFor(() =>
      expect(api.setProgramOrgChannels).toHaveBeenCalledWith(
        'p1',
        true,
        'too short - SOC triage rota covers this program'
      )
    )
  })

  it('an owner turns it off without a reason', async () => {
    setDelivery({ org_channels: true })
    api.setProgramOrgChannels.mockResolvedValue({})
    render(<ProgramNotifications program={program()} canManage={false} isOwner />)
    await userEvent.click(
      screen.getByRole('switch', { name: /Also send to organization channels/ })
    )
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).queryByLabelText(/Reason/)).toBeNull()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Stop sending' }))
    await waitFor(() => expect(api.setProgramOrgChannels).toHaveBeenCalledWith('p1', false, ''))
  })

  it('a refused step-up surfaces the API error and keeps the dialog open', async () => {
    api.setProgramOrgChannels.mockRejectedValue(
      new ApiClientError('Re-authentication required', 'STEP_UP_REQUIRED', 403)
    )
    render(<ProgramNotifications program={program()} canManage={false} isOwner />)
    await userEvent.click(
      screen.getByRole('switch', { name: /Also send to organization channels/ })
    )
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'quarterly SOC coverage review')
    await userEvent.click(
      within(dialog).getByRole('button', { name: 'Send to organization channels' })
    )
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Re-authentication required'))
    expect(screen.getByRole('alertdialog')).toBeInTheDocument()
    expect(mutate).not.toHaveBeenCalled()
  })
})
