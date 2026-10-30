import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'

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

  it('drops the address column for a read-only administrator (no addresses sent)', () => {
    render(<AdminActivityTable entries={[entry()]} />)
    expect(screen.queryByText('IP address')).not.toBeInTheDocument()
  })
})
