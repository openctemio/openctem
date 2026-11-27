import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ConnectionsList } from '../components/connections-list'
import { normalizePublisherHost } from '../lib/use-mcp-labels'
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
  it('shows a failed load as an error with Retry, not as "no applications"', () => {
    const onRetry = vi.fn()
    render(
      <ConnectionsList
        connections={undefined}
        isLoading={false}
        error={new Error('boom')}
        onRetry={onRetry}
        onRevoke={vi.fn()}
        emptyTitle="No connected applications"
        emptyDescription="none"
      />
    )
    expect(screen.queryByText('No connected applications')).not.toBeInTheDocument()
    expect(screen.getByText("Couldn't load connected applications")).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalled()
  })

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
    expect(screen.getByText('Published by assistant.example')).toBeInTheDocument()
    expect(screen.getByText('Findings')).toBeInTheDocument()
    // The owner column is the organization view only.
    expect(screen.queryByText('Alice')).not.toBeInTheDocument()

    // One row menu, as on the other lists.
    await userEvent.click(screen.getByRole('button', { name: 'Actions for Desk Assistant' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /Disconnect/ }))
    expect(onRevoke).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    fireEvent.click(within(dialog).getByRole('button', { name: /Disconnect/ }))
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

  it('badges a connection that reads all organization data and can limit it', async () => {
    const onScope = vi.fn(async () => {})
    render(
      <ConnectionsList
        connections={[
          { ...conn, full_data: true },
          { ...conn, id: 'g2', full_data: false },
        ]}
        isLoading={false}
        onRevoke={vi.fn()}
        onScope={onScope}
        emptyTitle="none"
        emptyDescription="none"
      />
    )
    // One badge and one menu item: the scoped connection has neither.
    expect(screen.getAllByText('All organization data')).toHaveLength(1)
    const menus = screen.getAllByRole('button', { name: 'Actions for Desk Assistant' })
    await userEvent.click(menus[1])
    expect(screen.queryByRole('menuitem', { name: 'Limit to own data' })).toBeNull()
    await userEvent.keyboard('{Escape}')
    await userEvent.click(menus[0])
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Limit to own data' }))
    await waitFor(() => expect(onScope).toHaveBeenCalledWith('g1'))
  })

  it('shows 20 rows, then more on request', async () => {
    const many = Array.from({ length: 23 }, (_, i) => ({
      ...conn,
      id: `g${i}`,
      client_name: `App ${i}`,
    }))
    render(
      <ConnectionsList
        connections={many}
        isLoading={false}
        onRevoke={vi.fn()}
        emptyTitle="none"
        emptyDescription="none"
      />
    )
    expect(screen.getAllByRole('listitem')).toHaveLength(20)
    expect(screen.getByText('20 of 23')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Show 3 more' }))
    expect(screen.getAllByRole('listitem')).toHaveLength(23)
    expect(screen.queryByRole('button', { name: /Show \d+ more/ })).toBeNull()
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

describe('normalizePublisherHost', () => {
  it('keeps a host name, lower-cased', () => {
    expect(normalizePublisherHost(' Desk.Example.NET ')).toBe('desk.example.net')
  })
  it('takes the host of a pasted address', () => {
    expect(normalizePublisherHost('https://desk.example.net/oauth/client.json')).toBe(
      'desk.example.net'
    )
  })
  it('refuses what the API refuses', () => {
    for (const bad of [
      '',
      'localhost',
      '*.example.com',
      'a.example/x',
      'a b.example',
      'x'.repeat(254) + '.com',
    ]) {
      expect(normalizePublisherHost(bad)).toBeNull()
    }
  })
})
