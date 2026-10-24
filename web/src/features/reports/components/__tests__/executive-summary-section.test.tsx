import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

let allowed = true
let state: { summary?: unknown; error?: unknown; isLoading: boolean; retry: () => void }

vi.mock('../../hooks/use-report-schedules', () => ({
  useExecutiveSummary: () => state,
  downloadExecutiveSummaryCsv: vi.fn(),
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => (allowed ? children : null),
  Permission: { DashboardRead: 'dashboard:read' },
}))

import { ExecutiveSummarySection } from '../executive-summary-section'

describe('ExecutiveSummarySection', () => {
  beforeEach(() => {
    allowed = true
    state = { isLoading: false, retry: vi.fn() }
  })

  it('hides Download CSV without the permission', () => {
    allowed = false
    render(<ExecutiveSummarySection />)
    expect(screen.queryByRole('button', { name: /download csv/i })).toBeNull()
  })

  it('shows Download CSV with the permission', () => {
    render(<ExecutiveSummarySection />)
    expect(screen.getByRole('button', { name: /download csv/i })).toBeInTheDocument()
  })

  it('renders the error state with retry instead of dashes', () => {
    state = { isLoading: false, error: new Error('x'), retry: vi.fn() }
    render(<ExecutiveSummarySection />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('formats the figures with the shared formatters', () => {
    state = {
      isLoading: false,
      retry: vi.fn(),
      summary: {
        risk_score_current: 42.34,
        findings_total: 7,
        p0_open: 1,
        sla_compliance_pct: 94.3,
      },
    }
    render(<ExecutiveSummarySection />)
    expect(screen.getByText('42.3 / 100')).toBeInTheDocument()
    expect(screen.getByText('94%')).toBeInTheDocument()
  })
})
