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

  it('one line: the countdown as a pill in the state colour, the state in its name, the KEV reason', () => {
    const soon = new Date(Date.now() + 5 * 3_600_000 + 60_000).toISOString()
    const { container } = wrap(<SlaDueChip status="warning" deadline={soon} kevCapped />)
    const pill = container.querySelector('[data-slot="sla-countdown"]') as HTMLElement
    expect(pill.textContent).toMatch(
      /findings\.sla\.warning\|Warning: .*findings\.slaDue\.leftHours\|In 5 h/
    )
    expect(pill.className).toContain('border')
    expect(pill.getAttribute('title')).toContain('Warning')
    // No second line: no stacked column, no visible "KEV cap" word.
    const chip = container.querySelector('[data-slot="sla-due-chip"]') as HTMLElement
    expect(chip.className).not.toContain('flex-col')
    expect(chip.className).toContain('whitespace-nowrap')
    const cap = container.querySelector('[data-slot="sla-kev-capped"]')
    expect(cap).not.toBeNull()
    expect(cap).toHaveAttribute('aria-label', expect.stringContaining('slaKevCapped'))
  })

  it('says overdue in days and shows no KEV marker without the cap', () => {
    const late = new Date(Date.now() - 4 * 86_400_000 - 60_000).toISOString()
    const { container } = wrap(<SlaDueChip status="overdue" deadline={late} />)
    expect(screen.getByText(/findings\.slaDue\.overdueDays\|4 d overdue/)).toBeInTheDocument()
    expect(container.querySelector('[data-slot="sla-kev-capped"]')).toBeNull()
  })

  it('on track is plain text, not a pill; a passed deadline reads as late at once', () => {
    const later = new Date(Date.now() + 9 * 86_400_000 + 60_000).toISOString()
    const { container, unmount } = wrap(<SlaDueChip status="on_track" deadline={later} />)
    const plain = container.querySelector('[data-slot="sla-countdown"]') as HTMLElement
    expect(plain.textContent).toContain('In 9 d')
    expect(plain.className).not.toContain('border')
    unmount()
    const past = new Date(Date.now() - 2 * 86_400_000 - 60_000).toISOString()
    const late = wrap(<SlaDueChip status="on_track" deadline={past} />)
    const pill = late.container.querySelector('[data-slot="sla-countdown"]') as HTMLElement
    expect(pill.className).toContain('text-destructive')
  })

  it('never ends in an ellipsis: the whole text shows and a count above 999 reads 999+', () => {
    const late = new Date(Date.now() - 109 * 86_400_000 - 60_000).toISOString()
    const { container, unmount } = wrap(<SlaDueChip status="overdue" deadline={late} kevCapped />)
    const pill = container.querySelector('[data-slot="sla-countdown"]') as HTMLElement
    expect(pill.textContent).toContain('109 d overdue')
    expect(pill.className).not.toMatch(/truncate|min-w-0|text-ellipsis/)
    expect(pill.className).toContain('shrink-0')
    const chip = container.querySelector('[data-slot="sla-due-chip"]') as HTMLElement
    expect(chip.className).not.toMatch(/min-w-0|max-w-full/)
    unmount()
    const ancient = new Date(Date.now() - 1500 * 86_400_000).toISOString()
    const old = wrap(<SlaDueChip status="exceeded" deadline={ancient} />)
    expect(
      (old.container.querySelector('[data-slot="sla-countdown"]') as HTMLElement).textContent
    ).toContain('999+ d overdue')
  })

  it('shows the state word when there is no deadline', () => {
    wrap(<SlaDueChip status="exceeded" />)
    expect(screen.getByText(/findings\.sla\.exceeded\|Exceeded/)).toBeInTheDocument()
  })

  it('says No SLA for a finding without one', () => {
    wrap(<SlaDueChip status="not_applicable" />)
    expect(screen.getByText(/findings\.slaDue\.none/)).toBeInTheDocument()
  })
})
