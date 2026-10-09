import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { ConfirmView } from '../components/confirm-view'

const ID = '0199b6a0-1c2d-7e3f-8a9b-0c1d2e3f4a5b'

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'Acme', slug: 'acme', role: 'member' } }),
}))

const pending = {
  id: ID,
  tool: 'add_finding_comment',
  summary: 'Add an internal comment to the finding "<script>x</script>":\n\ntriage note',
  client_name: 'Desk Assistant',
  status: 'pending',
  expired: false,
  expires_at: new Date(Date.now() + 300000).toISOString(),
}

describe('ConfirmView', () => {
  let fetchFn: ReturnType<typeof vi.fn>
  beforeEach(() => {
    fetchFn = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/approve') || url.endsWith('/deny'))
        return new Response(null, { status: 204 })
      return new Response(JSON.stringify(pending), { status: 200 })
    })
    vi.stubGlobal('fetch', fetchFn)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('shows the exact action as text and confirms it', async () => {
    render(<ConfirmView id={ID} />)
    expect(await screen.findByText('Desk Assistant wants to make a change')).toBeInTheDocument()
    // Rendered as text, never as markup.
    expect(screen.getByText(/<script>x<\/script>/)).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(screen.getByText('Confirmed')).toBeInTheDocument())
    expect(String(fetchFn.mock.calls[1][0])).toBe(`/api/v1/mcp-access/confirmations/${ID}/approve`)
  })

  it('cannot confirm an expired request', async () => {
    fetchFn.mockImplementationOnce(
      async () => new Response(JSON.stringify({ ...pending, expired: true }), { status: 200 })
    )
    render(<ConfirmView id={ID} />)
    expect(await screen.findByText('This request expired.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeDisabled()
  })

  it('says nothing to confirm for someone else or a bad link', async () => {
    fetchFn.mockImplementationOnce(async () => new Response(null, { status: 404 }))
    render(<ConfirmView id={ID} />)
    expect(await screen.findByText('Nothing to confirm')).toBeInTheDocument()
  })

  it('refuses a malformed id without calling the API', () => {
    render(<ConfirmView id="../x" />)
    expect(screen.getByText('This link is not a valid confirmation.')).toBeInTheDocument()
    expect(fetchFn).not.toHaveBeenCalled()
  })
})
