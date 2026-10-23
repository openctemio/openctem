import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { PriorityBadge } from '../priority-badge'
import { SeverityBadge } from '../severity-badge'
import { KevBadge } from '../kev-badge'
import { EpssChip } from '../epss-chip'
import { StatusLozenge } from '../status-lozenge'
import { DashedCircleGlyph } from '../status-glyphs'
import { FindingStatusBadge } from '@/features/findings/components/finding-status-badge'
import { ALL_FINDING_STATUSES, FINDING_STATUS_CONFIG } from '@/features/findings/types'
import { PRIORITY_ORDER } from '@/lib/priority-colors'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { STATUS_TONES } from '@/lib/status-colors'
import { slaStateClass, SLA_STATE_CLASS } from '@/lib/sla-colors'

const NAMES = { P0: 'Immediate', P1: 'Urgent', P2: 'Scheduled', P3: 'Track' }

describe('PriorityBadge', () => {
  it.each(PRIORITY_ORDER)('%s renders its label, aria-label and own token set', (pc) => {
    render(<PriorityBadge priorityClass={pc} />)
    const el = screen.getByText(pc).closest('[data-slot="priority-badge"]') as HTMLElement
    expect(el.getAttribute('data-priority')).toBe(pc)
    expect(el.getAttribute('aria-label')).toBe(`Priority ${pc}, ${NAMES[pc]}`)
    const n = pc.slice(1)
    expect(el.className).toContain(`bg-prio-${n}-bg`)
    expect(el.className).toContain(`text-prio-${n}-fg`)
    expect(el.className).toContain(`border-prio-${n}-border`)
    expect(el.querySelectorAll('svg rect')).toHaveLength(3)
  })

  it('fills 3, 2, 1, 0 bars from P0 to P3', () => {
    const filled = PRIORITY_ORDER.map((pc) => {
      const { container, unmount } = render(<PriorityBadge priorityClass={pc} />)
      const n = [...container.querySelectorAll('svg rect')].filter(
        (r) => r.getAttribute('opacity') === '1'
      ).length
      unmount()
      return n
    })
    expect(filled).toEqual([3, 2, 1, 0])
  })

  it('adds the class name with showWord', () => {
    render(<PriorityBadge priorityClass="P0" showWord />)
    expect(screen.getByText('P0 · Immediate')).toBeTruthy()
  })

  it('shows a dashed dash for a finding that is not prioritised', () => {
    render(<PriorityBadge priorityClass={null} />)
    const el = screen.getByLabelText('Not prioritised')
    expect(el.textContent).toBe('–')
    expect(el.getAttribute('data-priority')).toBe('none')
    expect(el.className).toContain('border-dashed')
  })

  it('never uses a severity, signal (teal) or raw palette class', () => {
    for (const pc of PRIORITY_ORDER) {
      const { container, unmount } = render(<PriorityBadge priorityClass={pc} />)
      expect(container.innerHTML).not.toMatch(/sev-|signal|teal|red-|orange-|yellow-|blue-|slate-/)
      unmount()
    }
  })

  it('is a square box in sans type, unlike the round severity pill', () => {
    render(<PriorityBadge priorityClass="P1" />)
    const el = screen.getByText('P1').closest('[data-slot="priority-badge"]') as HTMLElement
    expect(el.className).toContain('rounded-sm')
    expect(el.className).not.toContain('font-mono')
  })
})

describe('SeverityBadge', () => {
  it.each(SEVERITY_LEVELS)('%s renders its label, a shape mark and its own token set', (sev) => {
    const { container } = render(<SeverityBadge severity={sev} />)
    const el = container.querySelector('[data-slot="severity-badge"]') as HTMLElement
    expect(el.getAttribute('data-severity')).toBe(sev)
    expect(el.getAttribute('data-variant')).toBe('inline')
    expect(el.className).toContain(`text-sev-${sev}-text`)
    expect(el.textContent?.length).toBeGreaterThan(0)
    expect(el.querySelector('svg[aria-hidden]')).not.toBeNull()
    expect(el.className).not.toMatch(/prio-|signal|teal|rounded-full|border/)
  })

  it('gives every level a different shape', () => {
    const shapes = SEVERITY_LEVELS.map((sev) => {
      const { container, unmount } = render(<SeverityBadge severity={sev} />)
      const html = container.querySelector('svg')!.innerHTML
      unmount()
      return html
    })
    expect(new Set(shapes).size).toBe(SEVERITY_LEVELS.length)
  })

  it('shows none and informational as info', () => {
    const { container } = render(<SeverityBadge severity="none" />)
    expect(container.querySelector('[data-severity="info"]')).not.toBeNull()
  })

  it('renders an unknown or missing value as neutral text', () => {
    const { container } = render(<SeverityBadge severity="whatever" />)
    const el = container.querySelector('[data-slot="severity-badge"]') as HTMLElement
    expect(el.getAttribute('data-severity')).toBe('unknown')
    expect(el.className).toContain('text-muted-foreground')
  })

  it('keeps the round pill with a dot as the soft variant, for counts', () => {
    const { container } = render(<SeverityBadge severity="high" variant="soft" />)
    const el = container.querySelector('[data-slot="severity-badge"]') as HTMLElement
    expect(el.getAttribute('data-variant')).toBe('soft')
    expect(el.className).toContain('rounded-full')
    expect(el.querySelector('span[aria-hidden]')).not.toBeNull()
  })
})

describe('StatusLozenge and FindingStatusBadge', () => {
  it.each(STATUS_TONES)('tone %s uses its own token set', (tone) => {
    render(<StatusLozenge tone={tone} icon={DashedCircleGlyph} label={`L-${tone}`} />)
    const el = screen.getByText(`L-${tone}`)
    expect(el.getAttribute('data-tone')).toBe(tone)
    expect(el.className).toContain(`text-st-${tone}-fg`)
    expect(el.className).toContain('rounded-md')
  })

  it('shows every finding status as a sentence-case label with an icon and no animation', () => {
    for (const status of ALL_FINDING_STATUSES) {
      const { container, unmount } = render(<FindingStatusBadge status={status} />)
      const el = container.querySelector('[data-slot="status-lozenge"]') as HTMLElement
      expect(el.getAttribute('data-status')).toBe(status)
      expect(el.getAttribute('data-tone')).toBe(FINDING_STATUS_CONFIG[status].tone)
      expect(el.textContent).toBe(FINDING_STATUS_CONFIG[status].label)
      expect(el.textContent).not.toMatch(/ [A-Z]/)
      expect(el.querySelector('svg')).not.toBeNull()
      expect(el.innerHTML).not.toContain('animate-spin')
      unmount()
    }
  })

  it('tells new, confirmed and in progress apart by tone and icon', () => {
    const html = (s: 'new' | 'confirmed' | 'in_progress') => {
      const { container, unmount } = render(<FindingStatusBadge status={s} />)
      const out = {
        tone: container.firstElementChild!.getAttribute('data-tone'),
        icon: container.querySelector('svg')!.innerHTML,
      }
      unmount()
      return out
    }
    const [a, b, c] = [html('new'), html('confirmed'), html('in_progress')]
    expect(new Set([a.tone, b.tone, c.tone]).size).toBe(3)
    expect(new Set([a.icon, b.icon, c.icon]).size).toBe(3)
  })

  it('renders an unknown status as a quiet lozenge with the raw value', () => {
    render(<FindingStatusBadge status={'triage_x' as never} />)
    expect(screen.getByText('triage_x').getAttribute('data-tone')).toBe('closed')
  })
})

describe('KevBadge', () => {
  it('is a neutral chip with the KEV text and a coloured bolt', () => {
    render(<KevBadge />)
    const el = screen.getByText('KEV').closest('[data-slot="kev-badge"]') as HTMLElement
    expect(el.className).not.toMatch(/bg-destructive|sev-|prio-/)
    expect(el.className).toContain('text-foreground')
    expect(el.querySelector('svg')!.getAttribute('class')).toContain('text-sig-icon')
  })

  it('reads "past due" and turns the text red', () => {
    render(<KevBadge pastDue />)
    const el = screen.getByText(/KEV/).closest('[data-slot="kev-badge"]') as HTMLElement
    expect(el.textContent).toContain('KEV past due')
    expect(el.className).toContain('text-destructive')
  })

  it('reads "ransomware" for known ransomware use', () => {
    render(<KevBadge ransomware />)
    expect(
      screen.getByText(/ransomware/).closest('[data-slot="kev-badge"]')?.textContent
    ).toContain('KEV ransomware')
  })
})

describe('EpssChip', () => {
  it('renders nothing below the threshold', () => {
    const { container } = render(<EpssChip score={0.09} />)
    expect(container.innerHTML).toBe('')
    expect(render(<EpssChip score={null} />).container.innerHTML).toBe('')
  })

  it('shows a neutral chip from 10 percent', () => {
    render(<EpssChip score={0.97} />)
    const el = screen.getByLabelText('EPSS 97%')
    expect(el.textContent).toBe('EPSS97%')
    expect(el.className).not.toMatch(/sev-|prio-|destructive|warning/)
  })

  it('can always be shown on a detail page with threshold 0', () => {
    render(<EpssChip score={0.02} threshold={0} />)
    expect(screen.getByLabelText('EPSS 2%')).toBeTruthy()
  })
})

describe('label components source', () => {
  const root = path.resolve(__dirname, '..')
  const files = [
    'priority-badge.tsx',
    'priority-glyph.tsx',
    'severity-badge.tsx',
    'severity-glyph.tsx',
    'status-lozenge.tsx',
    'status-glyphs.tsx',
    'kev-badge.tsx',
    'epss-chip.tsx',
    '../../features/findings/components/finding-status-badge.tsx',
  ]
  it.each(files)('%s has no mono type, tiny text or spin', (f) => {
    const src = readFileSync(path.join(root, f), 'utf8')
    expect(src).not.toMatch(/font-mono|text-\[1[01]px\]|animate-spin/)
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
