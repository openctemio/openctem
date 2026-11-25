import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'

import { InvitationView } from '../invitation-view'

// Presentation of the invitation page on the entry parts: one h1 per state,
// the entry card, refusals in one banner with the alert role, a teal primary
// without a leading icon. Behaviour is covered by invitation-view.test.tsx.

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/session-navigation', () => ({ navigateAfterSessionChange: vi.fn() }))
vi.mock('@/features/auth/actions/local-auth-actions', () => ({
  startSessionMfaAction: vi.fn(),
  selectTenantAction: vi.fn(),
}))

const TOKEN = 'entry-test-token-entry-test-token-entry-0123'

function preview(over: { pending?: boolean; days?: number } = {}) {
  return {
    invitation: {
      id: 'i1',
      email: 'linh.tran@example.com',
      role: 'member',
      pending: over.pending ?? true,
      expires_at: new Date(Date.now() + (over.days ?? 7) * 86400000 - 60000).toISOString(),
      inviter_name: 'Alice',
    },
    tenant: { id: 't1', name: 'Example Org', slug: 'example-org' },
  }
}

function stubLookup(status: number, body: unknown) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(body), { status }))
  )
}

function card() {
  const el = document.querySelector('[data-entry="card"]')
  expect(el).not.toBeNull()
  return el as HTMLElement
}

describe('InvitationView on the entry parts', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
    window.history.replaceState(null, '', `/invitations#token=${TOKEN}`)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('loading: one busy entry card', () => {
    stubLookup(200, preview())
    render(<InvitationView hasSession />)
    expect(card()).toHaveAttribute('aria-busy', 'true')
  })

  it('default, signed in: one h1, teal Accept without a leading icon, Decline beside it', async () => {
    stubLookup(200, preview())
    render(<InvitationView hasSession />)
    const accept = await screen.findByRole('button', { name: /accept invitation/i })
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(accept).toHaveAttribute('data-variant', 'signal')
    expect(accept.querySelector('svg')).toBeNull()
    expect(screen.getByRole('button', { name: /^decline$/i })).toHaveAttribute(
      'data-variant',
      'outline'
    )
    expect(card()).toContainElement(accept)
  })

  it('default, signed out: the sign-in link is the teal primary', async () => {
    stubLookup(200, preview())
    render(<InvitationView hasSession={false} />)
    const signIn = await screen.findByRole('link', { name: /sign in to accept/i })
    expect(signIn).toHaveAttribute('data-variant', 'signal')
    expect(signIn.querySelector('svg')).toBeNull()
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
  })

  it('shows the expiry chip at three days or fewer', async () => {
    stubLookup(200, preview({ days: 2 }))
    render(<InvitationView hasSession />)
    await screen.findByRole('button', { name: /accept invitation/i })
    expect(document.querySelector('[data-slot="tone-chip"]')).not.toBeNull()
  })

  it('error: one card titled by the problem, the reason as a status, the way back', async () => {
    stubLookup(404, {})
    render(<InvitationView hasSession />)
    await waitFor(() =>
      expect(screen.getAllByRole('heading', { level: 1 }).map((h) => h.textContent)).toEqual([
        'This invitation link does not work',
      ])
    )
    expect(document.querySelectorAll('[data-slot="entry-banner"]')).toHaveLength(0)
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to the dashboard' })).toHaveAttribute('href', '/')
  })

  it('already accepted: one h1 and the organization row', async () => {
    stubLookup(200, preview({ pending: false }))
    render(<InvitationView hasSession />)
    expect(await screen.findByText('Example Org')).toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Open Example Org' })).toHaveAttribute(
      'data-variant',
      'signal'
    )
  })
})
