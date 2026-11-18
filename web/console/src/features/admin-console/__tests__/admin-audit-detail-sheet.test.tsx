import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const mocks = vi.hoisted(() => ({ data: undefined as unknown }))
vi.mock('swr', () => ({
  default: () => ({ data: mocks.data, isLoading: false, error: undefined, mutate: vi.fn() }),
}))

import { AdminAuditDetailSheet } from '../components/admin-audit-detail-sheet'

const base = {
  id: 'a1',
  admin_email: 'ann@corp.example',
  action: 'console.elevated',
  success: true,
  created_at: '2026-11-18T03:54:09Z',
}

const open = (patch: Record<string, unknown>) => {
  mocks.data = { ...base, ...patch }
  render(<AdminAuditDetailSheet entryId="a1" onClose={() => {}} />)
}

describe('administrator audit detail sheet', () => {
  it('shows no row for a value the record does not have', () => {
    open({})
    expect(screen.getByText('When')).toBeInTheDocument()
    for (const label of [
      'Request',
      'Response',
      'Resource',
      'Resource ID',
      'IP address',
      'Reason',
    ]) {
      expect(screen.queryByText(label)).toBeNull()
    }
    expect(screen.queryByText('-')).toBeNull()
  })

  it('shows the exact UTC time, with the relative time beside it', () => {
    open({})
    expect(screen.getByText('2026-11-18 03:54:09 UTC')).toBeInTheDocument()
    expect(document.querySelectorAll('time').length).toBe(2)
  })

  it('shows the reason from the stored request, as plain text', () => {
    open({
      request_method: 'POST',
      request_path: '/admin/x',
      response_status: 200,
      request_body: { reason: '<img src=x onerror=alert(1)> change window' },
    })
    expect(screen.getByText('Reason')).toBeInTheDocument()
    expect(screen.getByText('<img src=x onerror=alert(1)> change window')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
    expect(screen.getByText('POST /admin/x')).toBeInTheDocument()
    expect(screen.getByText('Response')).toBeInTheDocument()
  })

  it('titles the sheet with the translated action and keeps the code', () => {
    open({})
    expect(screen.getByText('Elevated access started')).toBeInTheDocument()
    expect(screen.getByText('console.elevated')).toBeInTheDocument()
  })
})
