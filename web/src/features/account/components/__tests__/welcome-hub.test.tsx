/**
 * The /welcome hub (api RFC-141): invitations with accept and decline, create
 * an organization only where the API's policy says so, and the guidance for a
 * self-hosted installation where only the administrator creates organizations.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { OnboardingOptions } from '@/features/auth/actions/local-auth-actions'
import { en, vi as vi_ } from '@/lib/i18n/dictionaries'

import { WelcomeHub } from '../welcome-hub'

const mocks = vi.hoisted(() => ({
  options: vi.fn(),
  accept: vi.fn(),
  decline: vi.fn(),
  start: vi.fn(),
}))

vi.mock('@/features/auth/actions/local-auth-actions', () => ({
  onboardingOptionsAction: mocks.options,
  onboardingAcceptAction: mocks.accept,
}))
vi.mock('@/features/auth/actions/account-space-actions', () => ({
  onboardingDeclineAction: mocks.decline,
  startAccountSessionAction: mocks.start,
}))
vi.mock('../../api', () => ({
  useProfile: () => ({ profile: { name: 'Alice', email: 'alice@acme.io' } }),
}))
vi.mock('@/features/tenant/components/create-team-form', () => ({
  CreateTeamForm: () => <form aria-label="create organization form" />,
}))
vi.mock('@/features/auth/components/resend-verification', () => ({
  ResendVerification: ({ email }: { email?: string }) => (
    <button type="button">resend to {email}</button>
  ),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

function options(over: Partial<OnboardingOptions> = {}): OnboardingOptions {
  return {
    email_verified: true,
    invitations: [],
    organizations: [],
    can_create_organization: false,
    pending_requests: 0,
    ...over,
  }
}

const INVITATIONS: OnboardingOptions['invitations'] = [
  {
    ref: 'ref-acme',
    organization_name: 'Acme Security',
    role: 'member',
    invited_by: 'Bob Lee',
    expires_at: new Date(Date.now() + 5 * 86_400_000).toISOString(),
  },
  {
    ref: 'ref-beta',
    organization_name: 'Beta Corp',
    role: 'viewer',
    expires_at: new Date(Date.now() + 86_400_000).toISOString(),
  },
]

async function renderHub(opts: OnboardingOptions) {
  mocks.options.mockResolvedValue({ success: true, options: opts })
  render(<WelcomeHub needsSession={false} />)
  await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument())
}

describe('WelcomeHub', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists the invitations with accept and decline, and the account links', async () => {
    await renderHub(options({ invitations: INVITATIONS }))
    expect(screen.getByText('Acme Security')).toBeInTheDocument()
    expect(screen.getByText('Beta Corp')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Join' })).toHaveLength(2)
    expect(screen.getAllByRole('button', { name: 'Decline' })).toHaveLength(2)
    expect(screen.getByRole('link', { name: /Profile/ })).toHaveAttribute('href', '/account')
    expect(screen.getByRole('link', { name: /Security/ })).toHaveAttribute(
      'href',
      '/account/security'
    )
    expect(screen.getByRole('link', { name: /Sessions/ })).toHaveAttribute(
      'href',
      '/account/security#sessions'
    )
    expect(screen.getByRole('link', { name: /Sign-in methods/ })).toHaveAttribute(
      'href',
      '/account/security#sign-in-methods'
    )
    expect(screen.getByRole('link', { name: /Preferences/ })).toHaveAttribute(
      'href',
      '/account/preferences'
    )
  })

  it('accepts an invitation by its reference', async () => {
    mocks.accept.mockResolvedValue({ success: true, status: 'requested', organizationName: 'x' })
    await renderHub(options({ invitations: INVITATIONS }))
    await userEvent.click(screen.getAllByRole('button', { name: 'Join' })[0])
    await waitFor(() => expect(mocks.accept).toHaveBeenCalledWith('ref-acme'))
  })

  it('declines only after a confirmation, by reference', async () => {
    mocks.decline.mockResolvedValue({ success: true })
    await renderHub(options({ invitations: INVITATIONS }))
    await userEvent.click(screen.getAllByRole('button', { name: 'Decline' })[1])
    expect(mocks.decline).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Beta Corp')
    await userEvent.click(screen.getAllByRole('button', { name: 'Decline' }).at(-1)!)
    await waitFor(() => expect(mocks.decline).toHaveBeenCalledWith('ref-beta'))
    // The list is read again after the decline.
    await waitFor(() => expect(mocks.options).toHaveBeenCalledTimes(2))
  })

  it('no invitations, creation forbidden (self-hosted): asks for an administrator, offers no create', async () => {
    await renderHub(options({ can_create_organization: false }))
    expect(screen.getByTestId('ask-administrator')).toHaveTextContent(
      'Ask your administrator to invite alice@acme.io'
    )
    expect(screen.queryByText('Create an organization')).not.toBeInTheDocument()
    expect(screen.queryByRole('form', { name: /create organization/i })).not.toBeInTheDocument()
    expect(screen.queryByText('Your invitations')).not.toBeInTheDocument()
    // The account links stay.
    expect(screen.getByText('Your account')).toBeInTheDocument()
  })

  it('invitations present, creation forbidden: still no create, still the guidance', async () => {
    await renderHub(options({ invitations: INVITATIONS, can_create_organization: false }))
    expect(screen.queryByText('Create an organization')).not.toBeInTheDocument()
    expect(screen.getByTestId('ask-administrator')).toBeInTheDocument()
  })

  it('creation allowed, nothing else offered: the form is open', async () => {
    await renderHub(options({ can_create_organization: true }))
    expect(screen.getByText('Create an organization')).toBeInTheDocument()
    expect(screen.getByRole('form', { name: /create organization/i })).toBeInTheDocument()
    expect(screen.queryByTestId('ask-administrator')).not.toBeInTheDocument()
  })

  it('creation allowed with invitations: create is one click away, after the invitations', async () => {
    await renderHub(options({ invitations: INVITATIONS, can_create_organization: true }))
    expect(screen.queryByRole('form', { name: /create organization/i })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Create an organization' }))
    expect(screen.getByRole('form', { name: /create organization/i })).toBeInTheDocument()
  })

  it('an unverified address lists nothing and offers the verification link', async () => {
    await renderHub(options({ email_verified: false }))
    expect(screen.getByText('Verify your email address')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'resend to alice@acme.io' })).toBeInTheDocument()
    expect(screen.queryByText('Your invitations')).not.toBeInTheDocument()
  })

  it('a failed load keeps the account links and offers a retry', async () => {
    mocks.options.mockResolvedValue({ success: false, error: 'boom' })
    render(<WelcomeHub needsSession={false} />)
    await screen.findByRole('button', { name: /retry/i })
    expect(screen.getByText('Your account')).toBeInTheDocument()
    expect(screen.queryByText('Create an organization')).not.toBeInTheDocument()
  })

  it('asks for the account token first when the browser holds only a refresh token', async () => {
    mocks.start.mockResolvedValue({ success: false, code: 'ERROR' })
    render(<WelcomeHub needsSession />)
    await waitFor(() => expect(mocks.start).toHaveBeenCalledTimes(1))
    // The options are not read before the session exists.
    expect(mocks.options).not.toHaveBeenCalled()
  })
})

describe('welcome hub text', () => {
  it('has en and vi text for every welcome key', () => {
    const enKeys = Object.keys(en).filter((k) => k.startsWith('auth.welcome.'))
    expect(enKeys.length).toBeGreaterThan(30)
    for (const key of enKeys) {
      expect((vi_ as Record<string, string>)[key], key).toBeTruthy()
    }
  })
})
