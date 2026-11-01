import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { ConsentView } from '../components/consent-view'
import { DeviceCodeView } from '../components/device-code-view'
import { formatUserCodeInput, normalizeUserCode } from '../lib/device-code'
import { buildSnippets, TERMINAL_CLIENT_ID } from '../lib/client-snippets'

const REQUEST_ID = '0199b6a0-1c2d-7e3f-8a9b-0c1d2e3f4a5b'

const tenant = {
  currentTenant: { id: 't1', slug: 'acme', name: 'Acme', role: 'member' },
  tenants: [{ id: 't1', name: 'Acme' }],
  loadTenants: vi.fn(),
  switchTeam: vi.fn(),
  isSwitching: false,
}
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => tenant }))

const push = vi.fn()
vi.mock('next/navigation', () => ({ useRouter: () => ({ push }) }))

vi.mock('../api/access-requests', () => ({
  requestPublisherAccess: vi.fn(),
  allowPublisher: vi.fn(),
}))

const deviceConsent = {
  id: REQUEST_ID,
  client_name: 'Terminal sign-in',
  client_id: 'octc_terminal',
  client_kind: 'organization',
  redirect_host: '',
  redirect_uri: '',
  loopback_only: false,
  verified: false,
  flow: 'device',
  requester_ip: '203.0.113.7',
  requester_user_agent: 'node',
  requested_at: new Date().toISOString(),
  your_ip: '198.51.100.4',
  same_address: false,
  scopes: [
    {
      scope: 'mcp:findings.read',
      title: 'Read findings',
      write: false,
      granted: true,
      not_allowed: false,
    },
  ],
  expires_at: new Date(Date.now() + 600000).toISOString(),
}

describe('device code helpers', () => {
  it('normalizes what people type the way the API does', () => {
    expect(normalizeUserCode('bcdf-ghjk')).toBe('BCDFGHJK')
    expect(normalizeUserCode(' BCDF GHJK ')).toBe('BCDFGHJK')
    expect(normalizeUserCode('ABCD-GHJK')).toBeNull() // vowel
    expect(normalizeUserCode('BCDF-GHJ')).toBeNull()
    expect(normalizeUserCode('BCDF-GHJK-L')).toBeNull()
  })
  it('formats input while typing', () => {
    expect(formatUserCodeInput('bcd')).toBe('BCD')
    expect(formatUserCodeInput('bcdfg')).toBe('BCDF-G')
    expect(formatUserCodeInput('b-c d!f0ghjkzz')).toBe('BCDF-GHJK')
  })
  it('builds snippets for this instance with the terminal client id', () => {
    const s = buildSnippets('https://ctem.example/api/v1/mcp')
    expect(s.claudeCode).toContain(
      'claude mcp add --transport http openctem https://ctem.example/api/v1/mcp'
    )
    expect(s.deviceBridge).toContain('--device-code')
    expect(s.deviceBridge).toContain(TERMINAL_CLIENT_ID)
    expect(JSON.parse(s.deviceBridgeJson).mcpServers.openctem.args).toContain(
      'https://ctem.example/api/v1/mcp'
    )
    // Never a token in any snippet.
    expect(Object.values(s).join('\n')).not.toMatch(/oct_|Bearer/)
  })
})

describe('DeviceCodeView', () => {
  let fetchFn: ReturnType<typeof vi.fn>
  beforeEach(() => {
    push.mockReset()
    fetchFn = vi.fn()
    vi.stubGlobal('fetch', fetchFn)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('enters the code and opens the consent page for the request', async () => {
    fetchFn.mockResolvedValue(
      new Response(JSON.stringify({ request_id: REQUEST_ID }), { status: 200 })
    )
    render(<DeviceCodeView />)
    fireEvent.change(screen.getByLabelText('Code'), { target: { value: 'vrwjxbjv' } })
    expect(screen.getByLabelText('Code')).toHaveValue('VRWJ-XBJV')
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(push).toHaveBeenCalledWith(`/oauth/consent?request=${REQUEST_ID}`))
    const [url, init] = fetchFn.mock.calls[0]
    expect(String(url)).toContain('/api/v1/oauth/device')
    expect(JSON.parse(init.body)).toEqual({ user_code: 'VRWJXBJV' })
  })

  it('says a code is not valid without saying why', async () => {
    fetchFn.mockResolvedValue(
      new Response(JSON.stringify({ message: 'Code not found' }), { status: 404 })
    )
    render(<DeviceCodeView />)
    fireEvent.change(screen.getByLabelText('Code'), { target: { value: 'BCDFGHJK' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText(/This code is not valid/)).toBeInTheDocument()
    expect(push).not.toHaveBeenCalled()
  })
})

describe('ConsentView for a terminal sign-in', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.endsWith('/approve')) {
          return new Response(JSON.stringify({ redirect_to: '' }), { status: 200 })
        }
        return new Response(JSON.stringify(deviceConsent), { status: 200 })
      })
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it('shows where the request came from and a warning, never a return address', async () => {
    render(<ConsentView requestId={REQUEST_ID} />)
    expect(await screen.findByText('A terminal asked to connect with a code')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.7')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.4')).toBeInTheDocument()
    expect(screen.getByText('Different address')).toBeInTheDocument()
    expect(screen.getByText('Did you start this sign-in yourself?')).toBeInTheDocument()
    expect(screen.queryByText('You will be sent back to')).not.toBeInTheDocument()
    expect(screen.queryByText('Unverified application')).not.toBeInTheDocument()
  })

  it('approving ends on a page that sends the person back to the terminal', async () => {
    render(<ConsentView requestId={REQUEST_ID} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Allow' }))
    expect(await screen.findByText('Terminal sign-in is connected')).toBeInTheDocument()
  })
})
