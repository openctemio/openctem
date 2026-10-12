import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { ConnectionsList } from '../components/connections-list'
import { parseHosts } from '../components/mcp-policy-card'
import type { McpConnection } from '../api/connections'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const conn: McpConnection = {
  id: 'g1',
  client_name: 'Desk Assistant',
  client_id: 'https://assistant.example/c.json',
  client_kind: 'metadata_document',
  client_host: 'assistant.example',
  user_id: 'u1',
  user_name: 'Alice',
  user_email: 'alice@example.com',
  scopes: ['mcp:findings.read'],
  created_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 86400000).toISOString(),
}

describe('ConnectionsList', () => {
  it('shows the application, its host and the access, and disconnects after confirmation', async () => {
    const onRevoke = vi.fn(async () => {})
    render(
      <ConnectionsList
        connections={[conn]}
        isLoading={false}
        onRevoke={onRevoke}
        emptyTitle="none"
        emptyDescription="none"
      />
    )
    expect(screen.getByText('Desk Assistant')).toBeInTheDocument()
    expect(screen.getByText('assistant.example')).toBeInTheDocument()
    expect(screen.getByText('Findings')).toBeInTheDocument()
    // The owner column is the organization view only.
    expect(screen.queryByText('Alice')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Disconnect/ }))
    expect(onRevoke).not.toHaveBeenCalled()
    const buttons = await screen.findAllByRole('button', { name: /Disconnect/ })
    fireEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(onRevoke).toHaveBeenCalledWith('g1'))
  })

  it('names the person in the organization view and marks unverified applications', () => {
    render(
      <ConnectionsList
        connections={[{ ...conn, client_kind: 'dynamic', client_host: undefined }]}
        isLoading={false}
        showUser
        onRevoke={vi.fn()}
        emptyTitle="none"
        emptyDescription="none"
      />
    )
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('Unverified')).toBeInTheDocument()
  })

  it('shows the empty state', () => {
    render(
      <ConnectionsList
        connections={[]}
        isLoading={false}
        onRevoke={vi.fn()}
        emptyTitle="Nothing here"
        emptyDescription="x"
      />
    )
    expect(screen.getByText('Nothing here')).toBeInTheDocument()
  })
})

describe('parseHosts', () => {
  it('splits lines and commas and lower-cases', () => {
    expect(parseHosts(' A.example\nb.example, c.example ,,')).toEqual([
      'a.example',
      'b.example',
      'c.example',
    ])
  })
})
