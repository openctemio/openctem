import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { slaCountdown } from '../../lib/sla'
import { SlaDueChip } from '../sla-due-chip'

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fb?: string, vars?: Record<string, string | number>) => {
      let s = typeof fb === 'string' ? fb : _k
      for (const [n, v] of Object.entries(vars ?? {})) s = s.replace(`{${n}}`, String(v))
      return `${_k}|${s}`
    },
  }),
}))

const NOW = Date.parse('2026-10-25T12:00:00Z')

describe('slaCountdown', () => {
  it('counts hours under two days and days beyond, before and past the deadline', () => {
    expect(slaCountdown('2026-10-25T17:30:00Z', NOW)).toEqual({
      overdue: false,
      unit: 'hours',
      count: 5,
    })
    expect(slaCountdown('2026-10-28T12:00:00Z', NOW)).toEqual({
      overdue: false,
      unit: 'days',
      count: 3,
    })
    expect(slaCountdown('2026-10-25T11:00:00Z', NOW)).toEqual({
      overdue: true,
      unit: 'hours',
      count: 1,
    })
    expect(slaCountdown('2026-10-20T12:00:00Z', NOW)).toEqual({
      overdue: true,
      unit: 'days',
      count: 5,
    })
    expect(slaCountdown('2026-10-25T12:10:00Z', NOW)).toEqual({
      overdue: false,
      unit: 'hours',
      count: 1,
    })
    expect(slaCountdown(undefined, NOW)).toBeNull()
    expect(slaCountdown('not a date', NOW)).toBeNull()
  })
})

describe('SlaDueChip', () => {
  const wrap = (ui: React.ReactNode) => render(<TooltipProvider>{ui}</TooltipProvider>)

  it('shows the status, the countdown, and why a KEV cap set the deadline', () => {
    const soon = new Date(Date.now() + 5 * 3_600_000 + 60_000).toISOString()
    const { container } = wrap(<SlaDueChip status="warning" deadline={soon} kevCapped />)
    expect(screen.getByText(/findings\.slaDue\.leftHours\|5 left/)).toBeInTheDocument()
    const cap = container.querySelector('[data-slot="sla-kev-capped"]')
    expect(cap).not.toBeNull()
    expect(cap).toHaveAttribute('aria-label', expect.stringContaining('slaKevCapped'))
  })

  it('says overdue in days and shows no KEV marker without the cap', () => {
    const late = new Date(Date.now() - 4 * 86_400_000 - 60_000).toISOString()
    const { container } = wrap(<SlaDueChip status="overdue" deadline={late} />)
    expect(screen.getByText(/findings\.slaDue\.overdueDays\|4 past due/)).toBeInTheDocument()
    expect(container.querySelector('[data-slot="sla-kev-capped"]')).toBeNull()
  })

  it('says No SLA for a finding without one', () => {
    wrap(<SlaDueChip status="not_applicable" />)
    expect(screen.getByText(/findings\.slaDue\.none/)).toBeInTheDocument()
  })
})
