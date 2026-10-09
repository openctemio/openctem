import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { ConsentView } from '../components/consent-view'
import { clientKindLabel, isRequestId, isSafeRedirect } from '../api/consent'

const REQUEST_ID = '0199b6a0-1c2d-7e3f-8a9b-0c1d2e3f4a5b'

const tenant = {
  currentTenant: { id: 't1', slug: 'acme', name: 'Acme', role: 'member' },
  tenants: [{ id: 't1', name: 'Acme' }],
  loadTenants: vi.fn(),
  switchTeam: vi.fn(),
  isSwitching: false,
}
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => tenant }))

const consent = {
  id: REQUEST_ID,
  client_name: 'Desk Assistant',
  client_id: 'https://assistant.example/oauth/client.json',
  client_kind: 'metadata_document',
  client_host: 'assistant.example',
  redirect_host: '127.0.0.1',
  redirect_uri: 'http://127.0.0.1:33418/callback',
  loopback_only: true,
  verified: true,
  scopes: [
    {
      scope: 'mcp:findings.read',
      title: 'Read findings',
      write: false,
      granted: true,
      not_allowed: false,
    },
    {
      scope: 'mcp:pentest.read',
      title: 'Read pentest campaigns',
      write: false,
      granted: false,
      not_allowed: false,
    },
  ],
  expires_at: new Date(Date.now() + 600000).toISOString(),
}

describe('ConsentView', () => {
  let fetchFn: ReturnType<typeof vi.fn>
  const assign = vi.fn()

  beforeEach(() => {
    fetchFn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/approve')) {
        return new Response(
          JSON.stringify({ redirect_to: 'http://127.0.0.1:33418/callback?code=c&state=s' }),
          {
            status: 200,
          }
        )
      }
      if (url.endsWith('/deny')) {
        return new Response(JSON.stringify({ redirect_to: 'javascript:alert(1)' }), { status: 200 })
      }
      expect(init?.method ?? 'GET').toBe('GET')
      return new Response(JSON.stringify(consent), { status: 200 })
    })
    vi.stubGlobal('fetch', fetchFn)
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign },
      writable: true,
    })
    assign.mockReset()
  })
  afterEach(() => vi.unstubAllGlobals())

  it('names the application, its host, the return host, the organization and the access', async () => {
    render(<ConsentView requestId={REQUEST_ID} />)
    expect(await screen.findByText('Connect Desk Assistant to OpenCTEM?')).toBeInTheDocument()
    expect(screen.getByText('Published by assistant.example')).toBeInTheDocument()
    expect(screen.getByText('127.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('Acme')).toBeInTheDocument()
    expect(screen.getByText('Read findings')).toBeInTheDocument()
    // Loopback-only clients carry the impersonation warning.
    expect(screen.getByText('Only continue if you started this')).toBeInTheDocument()
    expect(String(fetchFn.mock.calls[0][0])).toBe(`/api/v1/oauth/requests/${REQUEST_ID}`)
  })

  it('posts the approval with the CSRF header and follows the returned address', async () => {
    document.cookie = 'csrf_token=tok123; path=/'
    render(<ConsentView requestId={REQUEST_ID} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Allow' }))
    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith('http://127.0.0.1:33418/callback?code=c&state=s')
    )
    const [url, init] = fetchFn.mock.calls[1] as [string, RequestInit]
    expect(url).toBe(`/api/v1/oauth/requests/${REQUEST_ID}/approve`)
    expect(init.method).toBe('POST')
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('tok123')
  })

  it('never navigates to a non-http address', async () => {
    render(<ConsentView requestId={REQUEST_ID} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(
      await screen.findByText('The application gave an address that cannot be opened')
    ).toBeInTheDocument()
    expect(assign).not.toHaveBeenCalled()
  })

  it('refuses a malformed request id without calling the API', () => {
    render(<ConsentView requestId="../../api-keys" />)
    expect(screen.getByText('This link is not a valid connection request.')).toBeInTheDocument()
    expect(fetchFn).not.toHaveBeenCalled()
  })

  it('marks a self-registered client unverified', async () => {
    fetchFn.mockImplementationOnce(
      async () =>
        new Response(
          JSON.stringify({
            ...consent,
            client_kind: 'dynamic',
            client_host: undefined,
            verified: false,
          }),
          { status: 200 }
        )
    )
    render(<ConsentView requestId={REQUEST_ID} />)
    expect(await screen.findByText('Unverified application')).toBeInTheDocument()
  })

  it('explains and refuses an application the organization blocks', async () => {
    fetchFn.mockImplementationOnce(
      async () =>
        new Response(
          JSON.stringify({ ...consent, verified: false, blocked: 'client_not_allowed' }),
          { status: 200 }
        )
    )
    render(<ConsentView requestId={REQUEST_ID} />)
    expect(await screen.findByText('This application cannot be connected')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Allow' })).toBeDisabled()
  })

  it('cannot allow when nothing would be granted', async () => {
    fetchFn.mockImplementationOnce(
      async () =>
        new Response(
          JSON.stringify({
            ...consent,
            scopes: consent.scopes.map((s) => ({ ...s, granted: false })),
          }),
          {
            status: 200,
          }
        )
    )
    render(<ConsentView requestId={REQUEST_ID} />)
    expect(await screen.findByRole('button', { name: 'Allow' })).toBeDisabled()
  })
})

describe('consent helpers', () => {
  it('accepts only http(s) redirects', () => {
    expect(isSafeRedirect('https://app.example/cb?code=1')).toBe(true)
    expect(isSafeRedirect('http://127.0.0.1:5000/cb')).toBe(true)
    expect(isSafeRedirect('javascript:alert(1)')).toBe(false)
    expect(isSafeRedirect('data:text/html,x')).toBe(false)
    expect(isSafeRedirect('/relative')).toBe(false)
  })

  it('accepts only UUID request ids', () => {
    expect(isRequestId(REQUEST_ID)).toBe(true)
    expect(isRequestId('x')).toBe(false)
    expect(isRequestId(null)).toBe(false)
  })

  it('labels client kinds', () => {
    expect(clientKindLabel({ client_kind: 'organization' })).toBe('Registered by your organization')
    expect(clientKindLabel({ client_kind: 'dynamic' })).toBe('Unverified: registered itself')
  })
})
