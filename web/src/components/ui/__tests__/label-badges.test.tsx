import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { PriorityBadge } from '../priority-badge'
import { SeverityBadge } from '../severity-badge'
import { KevBadge } from '../kev-badge'
import { PRIORITY_ORDER } from '@/lib/priority-colors'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { slaStateClass, SLA_STATE_CLASS } from '@/lib/sla-colors'

describe('PriorityBadge', () => {
  it.each(PRIORITY_ORDER)('%s renders its label on its own token set', (pc) => {
    render(<PriorityBadge priorityClass={pc} />)
    const el = screen.getByText(pc)
    expect(el.getAttribute('data-priority')).toBe(pc)
    const n = pc.slice(1)
    expect(el.className).toContain(`bg-prio-${n}-bg`)
    expect(el.className).toContain(`text-prio-${n}-fg`)
    expect(el.className).toContain(`border-prio-${n}-border`)
  })

  it('never uses a severity, signal (teal) or raw palette class', () => {
    for (const pc of PRIORITY_ORDER) {
      const { container, unmount } = render(<PriorityBadge priorityClass={pc} />)
      expect(container.innerHTML).not.toMatch(/sev-|signal|teal|red-|orange-|yellow-|blue-|slate-/)
      unmount()
    }
  })

  it('is a square box, unlike the round severity pill', () => {
    render(<PriorityBadge priorityClass="P1" />)
    expect(screen.getByText('P1').className).toContain('rounded-sm')
  })
})

describe('SeverityBadge', () => {
  it.each(SEVERITY_LEVELS)('%s renders its label on its own token set', (sev) => {
    const { container } = render(<SeverityBadge severity={sev} />)
    const el = container.querySelector('[data-slot="severity-badge"]') as HTMLElement
    expect(el.getAttribute('data-severity')).toBe(sev)
    expect(el.className).toContain(`text-sev-${sev}-text`)
    expect(el.textContent?.length).toBeGreaterThan(0)
    expect(el.className).not.toMatch(/prio-|signal|teal/)
  })

  it('shows none and informational as info', () => {
    const { container } = render(<SeverityBadge severity="none" />)
    expect(container.querySelector('[data-severity="info"]')).not.toBeNull()
  })

  it('renders an unknown or missing value as a neutral pill', () => {
    const { container } = render(<SeverityBadge severity="whatever" />)
    const el = container.querySelector('[data-slot="severity-badge"]') as HTMLElement
    expect(el.getAttribute('data-severity')).toBe('unknown')
    expect(el.className).toContain('bg-muted')
  })

  it('is a round pill with a dot, unlike the priority box', () => {
    const { container } = render(<SeverityBadge severity="high" />)
    const el = container.querySelector('[data-slot="severity-badge"]') as HTMLElement
    expect(el.className).toContain('rounded-full')
    expect(el.querySelector('span[aria-hidden]')).not.toBeNull()
  })
})

describe('KevBadge', () => {
  it('shows the KEV text on a solid danger pill', () => {
    render(<KevBadge />)
    const el = screen.getByText('KEV').closest('[data-slot="kev-badge"]') as HTMLElement
    expect(el.className).toContain('bg-destructive')
    expect(el.className).not.toMatch(/sev-|prio-/)
  })
})

describe('SLA state classes', () => {
  it('give each state its own state-token pill and read unknown as n/a', () => {
    expect(SLA_STATE_CLASS.on_track).toContain('success')
    expect(SLA_STATE_CLASS.warning).toContain('warning')
    expect(SLA_STATE_CLASS.overdue).toContain('destructive')
    expect(SLA_STATE_CLASS.exceeded).toContain('destructive')
    expect(slaStateClass('nonsense')).toBe(SLA_STATE_CLASS.not_applicable)
    expect(slaStateClass(undefined)).toBe(SLA_STATE_CLASS.not_applicable)
    expect(slaStateClass('OVERDUE')).toBe(SLA_STATE_CLASS.overdue)
    for (const v of Object.values(SLA_STATE_CLASS)) expect(v).not.toMatch(/sev-|prio-|signal/)
  })
})
