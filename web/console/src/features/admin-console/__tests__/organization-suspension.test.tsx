import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { setOrganizationSuspended } from '../api/use-admin-organizations'
import {
  OrganizationStatusBadge,
  OrganizationSuspendedNotice,
  OrganizationSuspensionAction,
} from '../components/organization-suspension'
import type { AdminOrganization } from '../types'

vi.mock('../api/use-admin-organizations', async (orig) => ({
  ...(await orig<typeof import('../api/use-admin-organizations')>()),
  setOrganizationSuspended: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function org(patch: Partial<AdminOrganization> = {}): AdminOrganization {
  return {
    id: 'o1',
    name: 'Acme',
    slug: 'acme',
    created_at: '2026-10-01T00:00:00Z',
    active_members: 3,
    owner_emails: [],
    owner_count: 1,
    saml_enabled: false,
    active_identity_providers: 0,
    verified_domains: 0,
    sso_enforced: false,
    limits_apply: false,
    status: 'active',
    ...patch,
  }
}

describe('Organization suspension', () => {
  beforeEach(() => vi.clearAllMocks())

  it('suspends with a reason', async () => {
    const user = userEvent.setup()
    const onDone = vi.fn()
    vi.mocked(setOrganizationSuspended).mockResolvedValue({ status: 'suspended' })
    render(<OrganizationSuspensionAction org={org()} onDone={onDone} />)
    await user.click(screen.getByRole('button', { name: 'Suspend organization' }))
    await user.type(screen.getByLabelText(/^reason$/i), 'Abuse report 12: phishing pages')
    const buttons = screen.getAllByRole('button', { name: 'Suspend organization' })
    await user.click(buttons[buttons.length - 1])
    await waitFor(() =>
      expect(setOrganizationSuspended).toHaveBeenCalledWith(
        'o1',
        true,
        'Abuse report 12: phishing pages'
      )
    )
    await waitFor(() => expect(onDone).toHaveBeenCalled())
  })

  it('offers the lift on a suspended organization and shows why it is suspended', async () => {
    const user = userEvent.setup()
    vi.mocked(setOrganizationSuspended).mockResolvedValue({ status: 'active' })
    const suspended = org({
      status: 'suspended',
      suspended_reason: 'Unpaid invoice 2026-09',
      suspended_at: '2026-10-10T00:00:00Z',
    })
    render(
      <>
        <OrganizationStatusBadge org={suspended} />
        <OrganizationSuspendedNotice org={suspended} />
        <OrganizationSuspensionAction org={suspended} onDone={vi.fn()} />
      </>
    )
    expect(screen.getByTestId('org-suspended')).toHaveTextContent('Suspended')
    expect(screen.getByText('Reason: Unpaid invoice 2026-09')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Lift suspension' }))
    await user.type(screen.getByLabelText(/^reason$/i), 'Invoice paid, ticket 5521')
    const buttons = screen.getAllByRole('button', { name: 'Lift suspension' })
    await user.click(buttons[buttons.length - 1])
    await waitFor(() =>
      expect(setOrganizationSuspended).toHaveBeenCalledWith(
        'o1',
        false,
        'Invoice paid, ticket 5521'
      )
    )
  })

  it('shows nothing for an active organization', () => {
    const { container } = render(
      <>
        <OrganizationStatusBadge org={org()} />
        <OrganizationSuspendedNotice org={org()} />
      </>
    )
    expect(container).toBeEmptyDOMElement()
  })
})
