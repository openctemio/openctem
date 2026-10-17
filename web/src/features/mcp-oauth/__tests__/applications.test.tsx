/**
 * The Applications tab: members' requests (approve with a confirmation that
 * names the publisher, decline), the approved publishers list (validated
 * add, platform hosts read only) and the warned, confirmed switch for
 * unverified applications.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import type { McpPolicy } from '../api/connections'

const approve = vi.fn()
const deny = vi.fn()
const patch = vi.fn()
let requests = [
  {
    id: 'r1',
    client_host: 'desk.example.net',
    client_name: 'Desk Assistant',
    client_id: 'https://desk.example.net/oauth/client.json',
    scopes: ['mcp:findings.read', 'mcp:assets.read'],
    requester_name: 'Mark Member',
    request_count: 2,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
]

vi.mock('../api/access-requests', () => ({
  useAccessRequests: () => ({ data: { data: requests }, isLoading: false }),
  approveAccessRequest: (id: string) => approve(id),
  denyAccessRequest: (id: string) => deny(id),
}))
vi.mock('../api/connections', () => ({
  patchMcpPolicy: (current: unknown, p: unknown) => patch(current, p),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { AccessRequestsCard } from '../components/access-requests-card'
import { ApprovedPublishersCard } from '../components/approved-publishers-card'
import { UnverifiedAppsCard } from '../components/unverified-apps-card'

const policy: McpPolicy = {
  enabled: true,
  any_client: false,
  client_hosts: ['assistant.example.com'],
  scopes: [],
  api_keys_allowed: true,
  refresh_days: 0,
  effective_refresh_days: 90,
  require_dpop: false,
  max_tlp: 'amber',
  platform_client_hosts: ['platform-trusted.example'],
  available_scopes: [],
}

describe('Access requests', () => {
  beforeEach(() => {
    approve.mockReset().mockResolvedValue(undefined)
    deny.mockReset().mockResolvedValue(undefined)
  })

  it('shows who asked for which publisher and what it asks for', () => {
    render(<AccessRequestsCard canEdit />)
    expect(screen.getByText('Desk Assistant')).toBeInTheDocument()
    expect(screen.getByText('Published by desk.example.net')).toBeInTheDocument()
    expect(screen.getByText(/Requested by Mark Member · 2 request\(s\)/)).toBeInTheDocument()
    expect(screen.getByText('Findings')).toBeInTheDocument()
    expect(screen.getByText('Assets')).toBeInTheDocument()
  })

  it('approves only after a confirmation that names the publisher', async () => {
    render(<AccessRequestsCard canEdit />)
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(
      await screen.findByText('Approve applications published by desk.example.net?')
    ).toBeInTheDocument()
    expect(approve).not.toHaveBeenCalled()
    const buttons = screen.getAllByRole('button', { name: 'Approve' })
    fireEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(approve).toHaveBeenCalledWith('r1'))
  })

  it('declines', async () => {
    render(<AccessRequestsCard canEdit />)
    fireEvent.click(screen.getByRole('button', { name: 'Decline' }))
    const buttons = await screen.findAllByRole('button', { name: 'Decline' })
    fireEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(deny).toHaveBeenCalledWith('r1'))
  })

  it('offers no decision without settings:write', () => {
    render(<AccessRequestsCard canEdit={false} />)
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull()
  })

  it('has an empty state', () => {
    const saved = requests
    requests = []
    render(<AccessRequestsCard canEdit />)
    expect(screen.getByText('No waiting requests')).toBeInTheDocument()
    requests = saved
  })
})

describe('Approved publishers', () => {
  beforeEach(() => patch.mockReset().mockResolvedValue(policy))

  it('lists the organization and platform publishers; only its own are removable', () => {
    render(<ApprovedPublishersCard policy={policy} canEdit />)
    expect(screen.getByText('assistant.example.com')).toBeInTheDocument()
    expect(screen.getByText('platform-trusted.example')).toBeInTheDocument()
    expect(screen.getByText('Trusted by the platform')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /Remove/ })).toHaveLength(1)
  })

  it('validates the host and adds the host of a pasted address', async () => {
    render(<ApprovedPublishersCard policy={policy} canEdit />)
    fireEvent.click(screen.getByRole('button', { name: 'Add publisher' }))
    const input = await screen.findByLabelText('Host name')
    fireEvent.change(input, { target: { value: '*.example.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(await screen.findByText(/Enter a host name/)).toBeInTheDocument()
    expect(patch).not.toHaveBeenCalled()

    fireEvent.change(input, { target: { value: 'assistant.example.com' } })
    expect(await screen.findByText('This publisher is already approved.')).toBeInTheDocument()

    fireEvent.change(input, {
      target: { value: 'https://Desk.Example.net/oauth/client.json' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(patch).toHaveBeenCalled())
    expect(patch.mock.calls[0][1]).toEqual({
      client_hosts: ['assistant.example.com', 'desk.example.net'],
    })
  })

  it('is read only without settings:write', () => {
    render(<ApprovedPublishersCard policy={policy} canEdit={false} />)
    expect(screen.queryByRole('button', { name: 'Add publisher' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Remove/ })).toBeNull()
  })
})

describe('Unverified applications', () => {
  beforeEach(() => patch.mockReset().mockResolvedValue(policy))

  it('asks for confirmation before allowing them', async () => {
    render(<UnverifiedAppsCard policy={policy} canEdit />)
    fireEvent.click(screen.getByRole('button', { name: /Advanced: unverified applications/ }))
    fireEvent.click(await screen.findByRole('switch'))
    expect(await screen.findByText('Allow applications nobody vouches for?')).toBeInTheDocument()
    expect(patch).not.toHaveBeenCalled()
    const buttons = screen.getAllByRole('button', { name: 'Allow unverified applications' })
    fireEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(patch).toHaveBeenCalled())
    expect(patch.mock.calls[0][1]).toEqual({ any_client: true })
  })

  it('turns them off without a confirmation and is open while on', async () => {
    render(<UnverifiedAppsCard policy={{ ...policy, any_client: true }} canEdit />)
    fireEvent.click(screen.getByRole('switch'))
    await waitFor(() => expect(patch).toHaveBeenCalled())
    expect(patch.mock.calls[0][1]).toEqual({ any_client: false })
  })
})
