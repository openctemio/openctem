import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AdminActivityTable } from '../components/admin-activity-table'
import type { AdminAuditEntry } from '../types'

const entry = (patch: Partial<AdminAuditEntry> = {}): AdminAuditEntry => ({
  id: 'a1',
  admin_email: 'ann@corp.example',
  action: 'console.login',
  success: true,
  created_at: '2026-10-15T10:00:00Z',
  ...patch,
})

describe('AdminActivityTable', () => {
  it('shows the address column when rows carry addresses', () => {
    render(<AdminActivityTable entries={[entry({ ip_address: '203.0.113.7' })]} />)
    expect(screen.getAllByText('IP address').length).toBeGreaterThan(0)
    expect(screen.getAllByText('203.0.113.7').length).toBeGreaterThan(0)
  })

  it('shows the shared empty cell, not a dash, for a row without an address', () => {
    render(
      <AdminActivityTable
        entries={[entry({ ip_address: '203.0.113.7' }), entry({ id: 'a2', ip_address: '' })]}
      />
    )
    expect(screen.queryByText('-')).toBeNull()
    expect(screen.getAllByTitle('No address recorded').length).toBeGreaterThan(0)
  })

  it('drops the address column for a read-only administrator (no addresses sent)', () => {
    render(<AdminActivityTable entries={[entry()]} />)
    expect(screen.queryByText('IP address')).not.toBeInTheDocument()
  })

  it('is a named table whose action is the row name, on one line', () => {
    render(<AdminActivityTable entries={[entry({ action: 'organization.idp_create' })]} />)
    const table = screen.getByRole('table', { name: 'Administrator activity' })
    const row = within(table).getAllByRole('row')[1]
    expect(within(row).getByText('Identity provider added')).toBeInTheDocument()
    expect(within(row).getByText('organization.idp_create')).toBeInTheDocument()
  })

  it('shows a failed read in the table with Retry, the toolbar staying', async () => {
    const onRetry = vi.fn()
    render(
      <AdminActivityTable
        entries={[]}
        error={new Error('boom')}
        onRetry={onRetry}
        toolbarStart={<button type="button">Which events</button>}
      />
    )
    expect(screen.getByRole('button', { name: 'Which events' })).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: /retry/i }))
    expect(onRetry).toHaveBeenCalled()
  })

  it('tells "nothing yet" from "no match", and offers Clear filters', async () => {
    const { rerender } = render(<AdminActivityTable entries={[]} />)
    expect(screen.getByText('No administrator activity yet')).toBeInTheDocument()
    const onClear = vi.fn()
    rerender(
      <AdminActivityTable
        entries={[]}
        isFiltered
        onClearFilters={onClear}
        toolbarStart={<span />}
      />
    )
    expect(screen.getByText('No activity matches these filters')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: /clear filters/i }))
    expect(onClear).toHaveBeenCalled()
  })
})
