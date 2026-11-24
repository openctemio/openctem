import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import { AdminAuditChainBadge, AdminAuditChainStatus } from '../components/admin-audit-chain-status'
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

describe('AdminAuditChainBadge', () => {
  beforeEach(() => {
    state.current = { isLoading: false }
  })

  it('says the log is intact when every entry verifies, with the full sentence for a reader', () => {
    state.current = { data: report(), isLoading: false }
    render(<AdminAuditChainBadge />)
    expect(screen.getByText('Audit log intact')).toBeInTheDocument()
    expect(screen.getByText(/All 42 entries verify/)).toBeInTheDocument()
    expect(screen.getByTestId('audit-chain-intact')).toHaveAttribute(
      'title',
      expect.stringMatching(/All 42 entries verify/)
    )
  })

  it('never claims the log is intact when the check fails', () => {
    state.current = { error: new Error('down'), isLoading: false }
    render(<AdminAuditChainBadge />)
    expect(screen.queryByText('Audit log intact')).not.toBeInTheDocument()
    expect(screen.getByText('Audit log not checked')).toBeInTheDocument()
    expect(screen.getByText(/could not be checked/)).toBeInTheDocument()
  })

  it('says the log was tampered with when an entry does not verify', () => {
    state.current = {
      data: report({ breaks: [{ position: 7, id: 'row-7', reason: 'changed' }] }),
      isLoading: false,
    }
    render(<AdminAuditChainBadge />)
    expect(screen.getByText('Audit log tampered with')).toBeInTheDocument()
    expect(screen.queryByText('Audit log intact')).not.toBeInTheDocument()
  })

  it('holds its place while the chain is checked, claiming nothing to a reader', () => {
    state.current = { isLoading: true }
    render(<AdminAuditChainBadge />)
    const placeholder = screen.getByTestId('audit-chain-loading')
    expect(placeholder).toHaveAttribute('aria-busy', 'true')
    const hidden = placeholder.querySelector('span[aria-hidden="true"]') as HTMLElement
    expect(hidden.className).toMatch(/\binvisible\b/)
  })
})

describe('AdminAuditChainStatus', () => {
  beforeEach(() => {
    state.current = { isLoading: false }
  })

  it('draws nothing while the log verifies', () => {
    state.current = { data: report(), isLoading: false }
    const { container } = render(<AdminAuditChainStatus />)
    expect(container).toBeEmptyDOMElement()
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
})
