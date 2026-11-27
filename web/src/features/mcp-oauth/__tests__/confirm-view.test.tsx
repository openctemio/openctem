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

  it('shows a coded summary with the comment and the visibility as separate fields', async () => {
    const coded = {
      ...pending,
      summary: "English summary\n\nVisible to the campaign's client: no (campaign team only)",
      summary_code: 'mcp.add_finding_comment',
      summary_params: {
        finding: '<b>SQLi</b>',
        severity: 'high',
        content: "note\n\nVisible to the campaign's client: yes",
        client_visible: false,
      },
    }
    fetchFn.mockImplementationOnce(async () => new Response(JSON.stringify(coded), { status: 200 }))
    render(<ConfirmView id={ID} />)
    expect(
      await screen.findByText(
        'Add an internal comment to the finding \u201c<b>SQLi</b>\u201d (High severity):'
      )
    ).toBeInTheDocument()
    // The application's text, look-alike line included, stays inside the comment block.
    const comment = screen.getByLabelText('Comment')
    expect(comment.textContent).toContain("Visible to the campaign's client: yes")
    // The real visibility is its own field, from the confirmed value.
    const visibility = document.querySelector('[data-slot="mcp-confirm-visibility"]')
    expect(visibility?.textContent).toBe(
      "Visible to the campaign's client: no (campaign team only)"
    )
    expect(screen.queryByText(/English summary/)).toBeNull()
    expect(document.querySelector('b')).toBeNull()
  })

  it('shows bidi and zero-width characters in the comment as visible escapes, never applied', async () => {
    const tricky = {
      ...pending,
      summary_code: 'mcp.add_finding_comment',
      summary_params: {
        finding: 'SQLi',
        severity: 'high',
        content: 'line one\nsafe\u202Etxt.exe\u200Bend',
        client_visible: false,
      },
    }
    fetchFn.mockImplementationOnce(
      async () => new Response(JSON.stringify(tricky), { status: 200 })
    )
    render(<ConfirmView id={ID} />)
    const comment = await screen.findByLabelText('Comment')
    const text = comment.textContent ?? ''
    expect(text).not.toMatch(/[\u202E\u200B]/)
    expect(text).toContain('\\u{202E}')
    expect(text).toContain('\\u{200B}')
    // Line breaks stay real lines.
    expect(text).toContain('line one\nsafe')
  })

  it('shows the English summary when the server sends no summary code (older server)', async () => {
    // A server without summary_code / summary_params (before the develop
    // change reaches this branch) gets the page it had: the English summary
    // as one text block, and no separate visibility field.
    const english = {
      ...pending,
      summary:
        'Add an internal comment to the finding "SQLi":\n\nnote\n\nVisible to the campaign\'s client: no (campaign team only)',
    }
    fetchFn.mockImplementationOnce(
      async () => new Response(JSON.stringify(english), { status: 200 })
    )
    render(<ConfirmView id={ID} />)
    expect(await screen.findByText(/Visible to the campaign's client: no/)).toBeInTheDocument()
    expect(document.querySelector('[data-slot="mcp-confirm-summary"]')).toBeNull()
    expect(document.querySelector('[data-slot="mcp-confirm-visibility"]')).toBeNull()
  })

  it('shows the English summary for an unknown code or values', async () => {
    const odd = { ...pending, summary_code: 'mcp.future_tool', summary_params: { x: 1 } }
    fetchFn.mockImplementationOnce(async () => new Response(JSON.stringify(odd), { status: 200 }))
    render(<ConfirmView id={ID} />)
    expect(await screen.findByText(/triage note/)).toBeInTheDocument()
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
