import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import { AdminAuditChainStatus } from '../components/admin-audit-chain-status'
import type { AdminAuditChainReport } from '../api/use-admin-audit'

const state = vi.hoisted(() => ({
  current: { data: undefined, error: undefined, isLoading: false } as {
    data?: AdminAuditChainReport
    error?: unknown
    isLoading: boolean
  },
}))
vi.mock('../api/use-admin-audit', () => ({ useAdminAuditChain: () => state.current }))

const report = (patch: Partial<AdminAuditChainReport> = {}): AdminAuditChainReport => ({
  entries: 42,
  first_position: 1,
  last_position: 42,
  anchor_position: 0,
  breaks: [],
  truncated: false,
  verified_at: '2026-10-15T10:00:00Z',
  ...patch,
})

describe('AdminAuditChainStatus', () => {
  beforeEach(() => {
    state.current = { isLoading: false }
  })

  it('says the log is intact when every entry verifies', () => {
    state.current = { data: report(), isLoading: false }
    render(<AdminAuditChainStatus />)
    expect(screen.getByText('Audit log intact')).toBeInTheDocument()
    expect(screen.getByText(/All 42 entries verify/)).toBeInTheDocument()
  })

  it('names each entry that does not verify and why', () => {
    state.current = {
      data: report({
        breaks: [
          { position: 7, id: 'row-7', reason: 'changed' },
          { position: 9, id: 'row-9', reason: 'gap' },
        ],
      }),
      isLoading: false,
    }
    render(<AdminAuditChainStatus />)
    expect(screen.getByText('Audit log tampered with')).toBeInTheDocument()
    expect(screen.getByText(/#7 row-7: changed after it was written/)).toBeInTheDocument()
    expect(screen.getByText(/#9 row-9: rows are missing before it/)).toBeInTheDocument()
  })

  it('never claims the log is intact when the check fails', () => {
    state.current = { error: new Error('down'), isLoading: false }
    render(<AdminAuditChainStatus />)
    expect(screen.queryByText('Audit log intact')).not.toBeInTheDocument()
    expect(screen.getByText(/could not be checked/)).toBeInTheDocument()
  })
})
