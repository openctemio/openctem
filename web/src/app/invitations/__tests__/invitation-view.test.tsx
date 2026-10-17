import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { InvitationView } from '../invitation-view'

const push = vi.fn()
vi.mock('next/navigation', () => ({ useRouter: () => ({ push, refresh: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const TOKEN = 'GWEu-eZWS_bitGWEu-eZWS_bitGWEu-eZWS_bit0123'

const preview = {
  invitation: {
    id: 'i1',
    email: 'new.person@co.com',
    role: 'member',
    pending: true,
    expires_at: new Date(Date.now() + 7 * 86400000).toISOString(),
    inviter_name: 'Alice',
  },
  tenant: { id: 't1', name: 'Acme', slug: 'acme' },
}

type FetchCall = [input: RequestInfo | URL, init?: RequestInit]

function fetchMock(): ReturnType<typeof vi.fn> {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/lookup')) return new Response(JSON.stringify(preview), { status: 200 })
    if (url.endsWith('/decline')) return new Response(null, { status: 204 })
    return new Response(JSON.stringify({ role: 'member' }), { status: 200 })
  })
}

/** Every URL the page requested or showed must be free of the token. */
function expectTokenNeverInAUrl(fetchFn: ReturnType<typeof vi.fn>) {
  for (const [input] of fetchFn.mock.calls as FetchCall[]) {
    expect(String(input)).not.toContain(TOKEN)
  }
  expect(window.location.href).not.toContain(TOKEN)
  for (const a of Array.from(document.querySelectorAll('a'))) {
    expect(a.getAttribute('href') ?? '').not.toContain(TOKEN)
  }
}

describe('InvitationView', () => {
  let fetchFn: ReturnType<typeof vi.fn>

  beforeEach(() => {
    window.sessionStorage.clear()
    window.history.replaceState(null, '', `/invitations#token=${TOKEN}`)
    fetchFn = fetchMock()
    vi.stubGlobal('fetch', fetchFn)
    push.mockReset()
  })
  afterEach(() => vi.unstubAllGlobals())

  it('takes the token from the fragment, strips it from the URL, and sends it in the body', async () => {
    render(<InvitationView hasSession />)
    expect(await screen.findByText('Acme')).toBeInTheDocument()

    expect(window.location.hash).toBe('')
    expect(window.location.pathname).toBe('/invitations')

    const [input, init] = fetchFn.mock.calls[0] as FetchCall
    expect(String(input)).toBe('/api/v1/invitations/lookup')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({ token: TOKEN })
    expectTokenNeverInAUrl(fetchFn)
  })

  it('without a session offers sign in and "Create your account" without the token in returnTo', async () => {
    render(<InvitationView hasSession={false} />)

    const create = await screen.findByRole('link', { name: /create your account/i })
    const url = new URL(create.getAttribute('href') ?? '', 'http://x')
    expect(url.pathname).toBe('/register')
    expect(url.searchParams.get('returnTo')).toBe('/invitations')
    expect(url.searchParams.get('email')).toBe('new.person@co.com')

    const signIn = screen.getByRole('link', { name: /sign in to accept/i })
    const loginUrl = new URL(signIn.getAttribute('href') ?? '', 'http://x')
    expect(loginUrl.pathname).toBe('/login')
    expect(loginUrl.searchParams.get('returnTo')).toBe('/invitations')

    // Accept/Decline need a session; they are not offered.
    expect(screen.queryByRole('button', { name: /accept invitation/i })).toBeNull()
    expectTokenNeverInAUrl(fetchFn)
  })

  it('comes back from sign-in with the token kept for the tab', async () => {
    const first = render(<InvitationView hasSession={false} />)
    await screen.findByText('Acme')
    first.unmount()

    // Back from /login?returnTo=/invitations: no fragment any more.
    window.history.replaceState(null, '', '/invitations')
    render(<InvitationView hasSession />)
    expect(await screen.findByRole('button', { name: /accept invitation/i })).toBeInTheDocument()
    const [, init] = fetchFn.mock.calls[1] as FetchCall
    expect(JSON.parse(String(init?.body))).toEqual({ token: TOKEN })
  })

  it('accepts with the token in the body and forgets it', async () => {
    render(<InvitationView hasSession />)
    fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))
    await waitFor(() => expect(push).toHaveBeenCalledWith('/dashboard'))

    const accept = (fetchFn.mock.calls as FetchCall[]).find(([u]) => String(u).endsWith('/accept'))
    expect(accept).toBeDefined()
    expect(JSON.parse(String(accept?.[1]?.body))).toEqual({ token: TOKEN })
    expect(window.sessionStorage.length).toBe(0)
    expectTokenNeverInAUrl(fetchFn)
  })

  it('declines after confirming, with the token in the body, and says so', async () => {
    render(<InvitationView hasSession />)
    fireEvent.click(await screen.findByRole('button', { name: /^decline$/i }))
    const confirm = await screen.findAllByRole('button', { name: /^decline$/i })
    fireEvent.click(confirm[confirm.length - 1])
    expect(await screen.findByText('Invitation declined')).toBeInTheDocument()

    const decline = (fetchFn.mock.calls as FetchCall[]).find(([u]) =>
      String(u).endsWith('/decline')
    )
    expect(JSON.parse(String(decline?.[1]?.body))).toEqual({ token: TOKEN })
    expect(window.sessionStorage.length).toBe(0)
    expect(push).not.toHaveBeenCalled()
  })

  it('offers decline without a session too', async () => {
    render(<InvitationView hasSession={false} />)
    expect(await screen.findByRole('button', { name: /^decline$/i })).toBeInTheDocument()
  })

  it('shows what accepting gives: roles with risk, teams, outside status, end of access, two-factor', async () => {
    const rich = {
      ...preview,
      invitation: {
        ...preview.invitation,
        roles: [
          {
            id: 'r1',
            name: 'Security analyst',
            slug: 'security-analyst',
            is_system: false,
            summary: {
              risk: 'medium',
              reasons: [],
              areas: [{ area: 'findings', level: 'change' }],
            },
          },
        ],
        teams: [{ id: 'g1', name: 'Red team' }],
        member_kind: 'external',
        access_expires_at: '2026-12-31T23:59:59Z',
        mfa_required: true,
        mfa_reason: 'outside_privileged',
      },
    }
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(rich), { status: 200 }))
    )
    render(<InvitationView hasSession />)
    expect(await screen.findByText('Security analyst')).toBeInTheDocument()
    expect(screen.getByText('Red team')).toBeInTheDocument()
    expect(screen.getByText(/You join from outside Acme/)).toBeInTheDocument()
    expect(screen.getByText(/Your access ends on/)).toBeInTheDocument()
    expect(
      screen.getByText(/set up two-factor authentication before you can open Acme/)
    ).toBeInTheDocument()
  })

  it('says a newcomer without teams sees no data yet', async () => {
    const plain = { ...preview, invitation: { ...preview.invitation, roles: [], teams: [] } }
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(plain), { status: 200 }))
    )
    render(<InvitationView hasSession />)
    expect(await screen.findByText(/No teams yet/)).toBeInTheDocument()
    expect(screen.getByText('Your access has no end date.')).toBeInTheDocument()
  })

  it('without a token says the link is incomplete and calls nothing', async () => {
    window.history.replaceState(null, '', '/invitations')
    render(<InvitationView hasSession />)
    expect(await screen.findByText(/invitation link is incomplete/i)).toBeInTheDocument()
    expect(fetchFn).not.toHaveBeenCalled()
  })

  it('names the inviter when the lookup carries a name', async () => {
    render(<InvitationView hasSession />)
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    expect(screen.queryByText('A team member')).toBeNull()
  })

  it.each([undefined, '', '  '])(
    'falls back to "A team member" for inviter_name %j',
    async (name) => {
      const unnamed = { ...preview, invitation: { ...preview.invitation, inviter_name: name } }
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => new Response(JSON.stringify(unnamed), { status: 200 }))
      )
      render(<InvitationView hasSession />)
      expect(await screen.findByText('A team member')).toBeInTheDocument()
    }
  )
})
