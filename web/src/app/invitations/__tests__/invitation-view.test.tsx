import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { InvitationView } from '../invitation-view'

const push = vi.fn()
vi.mock('next/navigation', () => ({ useRouter: () => ({ push, refresh: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

// A full page load in the browser; here, what the page asks for.
const navigate = vi.fn()
vi.mock('@/lib/session-navigation', () => ({
  navigateAfterSessionChange: (...a: unknown[]) => navigate(...a),
}))

const startSessionMfaAction = vi.fn()
const selectTenantAction = vi.fn()
vi.mock('@/features/auth/actions/local-auth-actions', () => ({
  startSessionMfaAction: (...a: unknown[]) => startSessionMfaAction(...a),
  selectTenantAction: (...a: unknown[]) => selectTenantAction(...a),
}))
// The real step is covered by its own tests; here only its wiring matters.
vi.mock('@/features/auth/components/mfa-step', () => ({
  MfaStep: ({
    purpose,
    orgs,
    onDone,
  }: {
    purpose: string
    orgs?: string[]
    onDone: (r: { success: boolean; requiresTenantSelection?: boolean }) => void
  }) => (
    <div>
      <span>{`step:${purpose}:${(orgs ?? []).join(',')}`}</span>
      <button onClick={() => onDone({ success: true, requiresTenantSelection: true })}>
        finish step
      </button>
    </div>
  ),
}))

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
    navigate.mockReset()
    selectTenantAction.mockReset()
    selectTenantAction.mockResolvedValue({ success: true })
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
    await waitFor(() => expect(navigate).toHaveBeenCalled())

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

  it('shows the console text for a refusal code, never the server sentence', async () => {
    fetchFn.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/lookup')) return new Response(JSON.stringify(preview), { status: 200 })
      return new Response(
        JSON.stringify({
          code: 'INVITATION_MEMBERSHIP_SUSPENDED',
          message: 'SERVER SENTENCE about the team',
        }),
        { status: 400 }
      )
    })
    render(<InvitationView hasSession />)
    fireEvent.click(await screen.findByRole('button', { name: /accept/i }))

    expect(
      await screen.findByText(/Your access to this organization is suspended/)
    ).toBeInTheDocument()
    expect(screen.queryByText(/SERVER SENTENCE/)).not.toBeInTheDocument()
  })

  describe('organization requires two-factor authentication after joining', () => {
    function mfaRefused() {
      fetchFn = vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith('/lookup')) return new Response(JSON.stringify(preview), { status: 200 })
        if (url.endsWith('/accept-with-refresh')) {
          return new Response(
            JSON.stringify({ code: 'MFA_ENROLLMENT_REQUIRED', message: 'requires 2FA' }),
            { status: 403 }
          )
        }
        return new Response(JSON.stringify({ message: 'no session' }), { status: 401 })
      })
      vi.stubGlobal('fetch', fetchFn)
    }

    beforeEach(() => {
      startSessionMfaAction.mockReset()
      selectTenantAction.mockReset()
    })

    it('shows the joined card and the second-factor step instead of an error, then opens the org', async () => {
      mfaRefused()
      startSessionMfaAction.mockResolvedValue({ success: true, purpose: 'enroll', orgs: ['Acme'] })
      selectTenantAction.mockResolvedValue({ success: true })
      render(<InvitationView hasSession />)
      fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))

      expect(await screen.findByText('You have joined Acme')).toBeInTheDocument()
      expect(screen.getByText('Set up two-factor authentication to open it.')).toBeInTheDocument()
      expect(await screen.findByText('step:enroll:Acme')).toBeInTheDocument()
      expect(screen.queryByText(/cannot accept/i)).toBeNull()
      expect(screen.queryByText(/sign in again/i)).toBeNull()
      expect(push).not.toHaveBeenCalled()

      fireEvent.click(screen.getByRole('button', { name: 'finish step' }))
      await waitFor(() => expect(navigate).toHaveBeenCalledWith('/', expect.anything()))
      expect(push).not.toHaveBeenCalled()
      // Several organizations: the invited one is selected explicitly.
      expect(selectTenantAction).toHaveBeenCalledWith('t1')
      expect(window.sessionStorage.length).toBe(0)
    })

    it('says precisely what failed and retries; it does not send the person to sign in', async () => {
      mfaRefused()
      startSessionMfaAction
        .mockResolvedValueOnce({ success: false, error: 'Two-factor is not available here.' })
        .mockResolvedValueOnce({ success: true, purpose: 'verify' })
      render(<InvitationView hasSession />)
      fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))

      expect(await screen.findByText('Two-factor is not available here.')).toBeInTheDocument()
      expect(push).not.toHaveBeenCalled()
      fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
      expect(await screen.findByText('step:verify:')).toBeInTheDocument()
      expect(startSessionMfaAction).toHaveBeenCalledTimes(2)
    })

    it('goes to sign-in only when the session really expired', async () => {
      mfaRefused()
      startSessionMfaAction.mockResolvedValue({ success: false, sessionExpired: true })
      render(<InvitationView hasSession />)
      fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))
      await waitFor(() => expect(push).toHaveBeenCalledTimes(1))
      expect(String(push.mock.calls[0][0])).toContain('/login?returnTo=')
    })
  })
  describe('after accepting, the person lands in the organization they joined', () => {
    const LANDED = {
      replace: true,
      flash: { kind: 'success', title: 'You joined Acme.' },
    }

    function answers(map: Record<string, () => Response>) {
      fetchFn = vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith('/lookup')) return new Response(JSON.stringify(preview), { status: 200 })
        for (const [suffix, answer] of Object.entries(map)) {
          if (url.endsWith(suffix)) return answer()
        }
        return new Response(null, { status: 500 })
      })
      vi.stubGlobal('fetch', fetchFn)
    }

    it('signed in with another organization: selects the joined one, then a full page load', async () => {
      answers({
        '/accept': () => new Response(JSON.stringify({ role: 'member' }), { status: 200 }),
      })
      render(<InvitationView hasSession />)
      fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))

      await waitFor(() => expect(navigate).toHaveBeenCalledWith('/', LANDED))
      // The session is moved to the invited organization (the API checks membership).
      expect(selectTenantAction).toHaveBeenCalledWith('t1')
      expect(selectTenantAction.mock.invocationCallOrder[0]).toBeLessThan(
        navigate.mock.invocationCallOrder[0]
      )
      // Never a client-side push to the home page with the previous session.
      expect(push).not.toHaveBeenCalled()
      expect(window.sessionStorage.length).toBe(0)
    })

    it('signed in without an organization (refresh path): lands in the joined one', async () => {
      answers({
        '/accept': () => new Response(JSON.stringify({ code: 'UNAUTHORIZED' }), { status: 401 }),
        '/accept-with-refresh': () =>
          new Response(JSON.stringify({ tenant_id: 't1' }), { status: 200 }),
      })
      render(<InvitationView hasSession />)
      fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))

      await waitFor(() => expect(navigate).toHaveBeenCalledWith('/', LANDED))
      expect(selectTenantAction).toHaveBeenCalledWith('t1')
      expect(push).not.toHaveBeenCalled()
    })

    it('organization requires two-factor at selection: the step, not an error or a redirect', async () => {
      answers({
        '/accept': () => new Response(JSON.stringify({ role: 'member' }), { status: 200 }),
      })
      selectTenantAction.mockResolvedValue({ success: false, code: 'MFA_ENROLLMENT_REQUIRED' })
      startSessionMfaAction.mockResolvedValue({ success: true, purpose: 'enroll', orgs: ['Acme'] })
      render(<InvitationView hasSession />)
      fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))

      expect(await screen.findByText('You have joined Acme')).toBeInTheDocument()
      expect(navigate).not.toHaveBeenCalled()
      expect(push).not.toHaveBeenCalled()
    })

    it('selection failed: shows it accepted, says so, and offers "Open Acme", which retries', async () => {
      answers({
        '/accept': () => new Response(JSON.stringify({ role: 'member' }), { status: 200 }),
      })
      selectTenantAction.mockResolvedValueOnce({ success: false, error: 'boom' })
      render(<InvitationView hasSession />)
      fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))

      expect(await screen.findByText(/Could not open Acme/)).toBeInTheDocument()
      expect(navigate).not.toHaveBeenCalled()
      fireEvent.click(screen.getByRole('button', { name: 'Open Acme' }))
      await waitFor(() => expect(navigate).toHaveBeenCalledWith('/', LANDED))
      expect(selectTenantAction).toHaveBeenCalledTimes(2)
    })

    it('session gone at selection: sign in again (the membership exists)', async () => {
      answers({
        '/accept': () => new Response(JSON.stringify({ role: 'member' }), { status: 200 }),
      })
      selectTenantAction.mockResolvedValue({ success: false, code: 'SESSION_EXPIRED' })
      render(<InvitationView hasSession />)
      fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))
      await waitFor(() => expect(navigate).toHaveBeenCalledWith('/login', { replace: true }))
    })

    it('accepted meanwhile in a second tab: shows it accepted with "Open Acme", no error', async () => {
      let accepted = false
      fetchFn = vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith('/lookup')) {
          const body = accepted
            ? { ...preview, invitation: { ...preview.invitation, pending: false } }
            : preview
          return new Response(JSON.stringify(body), { status: 200 })
        }
        accepted = true
        return new Response(
          JSON.stringify({ code: 'VALIDATION', message: 'no longer available' }),
          { status: 400 }
        )
      })
      vi.stubGlobal('fetch', fetchFn)
      render(<InvitationView hasSession />)
      fireEvent.click(await screen.findByRole('button', { name: /accept invitation/i }))

      expect(await screen.findByText('Invitation already accepted')).toBeInTheDocument()
      expect(screen.queryByText(/cannot accept/i)).toBeNull()
      fireEvent.click(screen.getByRole('button', { name: 'Open Acme' }))
      await waitFor(() => expect(navigate).toHaveBeenCalledWith('/', LANDED))
    })
  })

  describe('an invitation already accepted', () => {
    beforeEach(() => {
      vi.stubGlobal(
        'fetch',
        vi.fn(
          async () =>
            new Response(
              JSON.stringify({ ...preview, invitation: { ...preview.invitation, pending: false } }),
              { status: 200 }
            )
        )
      )
    })

    it('signed in: offers "Open Acme" and lands there', async () => {
      render(<InvitationView hasSession />)
      expect(await screen.findByText('Invitation already accepted')).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /go to sign in/i })).toBeNull()
      fireEvent.click(screen.getByRole('button', { name: 'Open Acme' }))
      await waitFor(() => expect(selectTenantAction).toHaveBeenCalledWith('t1'))
      await waitFor(() =>
        expect(navigate).toHaveBeenCalledWith('/', {
          replace: true,
          flash: { kind: 'success', title: 'You joined Acme.' },
        })
      )
    })

    it('signed out: offers sign in, not "Open"', async () => {
      render(<InvitationView hasSession={false} />)
      expect(await screen.findByRole('button', { name: /go to sign in/i })).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /^open /i })).toBeNull()
    })

    it('expired: no "Open"', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn(
          async () =>
            new Response(
              JSON.stringify({
                ...preview,
                invitation: {
                  ...preview.invitation,
                  pending: false,
                  expires_at: new Date(Date.now() - 86400000).toISOString(),
                },
              }),
              { status: 200 }
            )
        )
      )
      render(<InvitationView hasSession />)
      expect(await screen.findByText('Invitation expired')).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /^open /i })).toBeNull()
    })
  })
})
