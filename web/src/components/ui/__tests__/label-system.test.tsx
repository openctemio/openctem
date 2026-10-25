import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { Globe } from 'lucide-react'

import { HealthStatus } from '../health-status'
import { SignalChip, DueChip } from '../signal-chip'
import { KevBadge } from '../kev-badge'
import { EpssChip } from '../epss-chip'
import { Tag } from '../tag'
import { Counter } from '../counter'
import { Marker, MARKER_KINDS } from '../marker'
import { SeverityBadge } from '../severity-badge'
import { StatusLozenge } from '../status-lozenge'
import { HEALTH_STATES } from '@/lib/health-colors'
import { TAG_PALETTE, TAG_SWATCH_CLASS, isTagPaletteName } from '@/lib/tag-colors'

const WORDS = {
  ok: 'OK',
  run: 'Running',
  queued: 'Queued',
  warn: 'Needs attention',
  down: 'Down',
  paused: 'Paused',
  off: 'Off',
  unknown: 'Unknown',
}

/** Nothing in a label may spin or pulse. */
function expectStatic(el: Element) {
  expect(el.outerHTML).not.toMatch(/animate-(spin|ping|pulse)/)
  expect(el.querySelectorAll('animate, animateTransform')).toHaveLength(0)
}

describe('HealthStatus', () => {
  it.each(HEALTH_STATES)('%s shows its text, an icon and no container or motion', (state) => {
    const { container } = render(<HealthStatus state={state} />)
    const el = container.querySelector('[data-slot="health-status"]') as HTMLElement
    expect(el.getAttribute('data-health')).toBe(state)
    expect(el.getAttribute('data-state')).toBeNull()
    expect(screen.getByText(WORDS[state])).toBeTruthy()
    expect(el.querySelector('svg[aria-hidden="true"]')).toBeTruthy()
    expect(el.className).not.toMatch(/\bbg-|\bborder\b|rounded/)
    expect(el.className).not.toMatch(/uppercase|font-mono|text-\[(9|10|11)px\]/)
    expectStatic(el)
  })

  it('uses the given label and a separate detail, with no separator glyph', () => {
    const { container } = render(<HealthStatus state="run" label="Running" detail="42%" />)
    expect(screen.getByText('Running')).toBeTruthy()
    expect(screen.getByText('42%')).toBeTruthy()
    expect(container.textContent).not.toMatch(/[·•∙]/)
  })

  it('writes the domain value to data-state and renders several details apart', () => {
    const { container } = render(
      <HealthStatus
        state="warn"
        label="Partial"
        value="partial"
        detail={['42%', '3 unreachable']}
      />
    )
    expect(container.querySelector('[data-state="partial"]')).toBeTruthy()
    expect(screen.getByText('42%')).toBeTruthy()
    expect(screen.getByText('3 unreachable')).toBeTruthy()
    expect(container.textContent).not.toMatch(/[·•∙,]/)
  })

  it('colours only the icon: the text stays in the foreground', () => {
    const { container } = render(<HealthStatus state="down" label="Offline" />)
    expect(container.querySelector('svg')?.getAttribute('class')).toContain('text-hl-down')
    expect(container.querySelector('[data-slot="health-status"]')?.className).toContain(
      'text-foreground'
    )
  })

  it('quiets the text of the off and unknown states', () => {
    const { container } = render(<HealthStatus state="unknown" label="Never connected" />)
    expect(container.querySelector('[data-slot="health-status"]')?.className).toContain(
      'text-muted-foreground'
    )
  })

  it('iconOnly drops the text and names itself for assistive tech', () => {
    render(<HealthStatus state="warn" iconOnly label="Degraded" detail="3 late" />)
    const el = screen.getByRole('img', { name: 'Degraded, 3 late' })
    expect(el.getAttribute('title')).toBe('Degraded, 3 late')
    expect(el.textContent).toBe('')
  })

  it('caps the label at 200px with a tooltip', () => {
    render(<HealthStatus state="ok" label="A very long label" />)
    const t = screen.getByText('A very long label')
    expect(t.className).toContain('max-w-[200px]')
    expect(t.className).toContain('truncate')
    expect(t.getAttribute('title')).toBe('A very long label')
  })
})

describe('SignalChip', () => {
  it('is a neutral chip: text in the foreground, a muted icon', () => {
    const { container } = render(<SignalChip icon={Globe}>Internet-facing</SignalChip>)
    const el = container.querySelector('[data-slot="signal-chip"]') as HTMLElement
    expect(el.getAttribute('data-tone')).toBe('neutral')
    expect(el.className).toContain('text-foreground')
    expect(el.className).not.toContain('text-destructive')
    expect(el.querySelector('svg')?.getAttribute('class')).toContain('text-muted-foreground')
  })

  it('alert tone reddens the icon, and the text only when asked', () => {
    const { container, rerender } = render(
      <SignalChip icon={Globe} tone="alert">
        Alert
      </SignalChip>
    )
    expect(container.querySelector('svg')?.getAttribute('class')).toContain('text-sig-icon')
    expect(container.firstElementChild?.className).not.toContain('text-destructive')
    rerender(
      <SignalChip icon={Globe} tone="alert" alertText>
        Alert
      </SignalChip>
    )
    expect(container.firstElementChild?.className).toContain('text-destructive')
  })
})

describe('KevBadge and EpssChip presets', () => {
  it('KevBadge keeps its API on a SignalChip', () => {
    const { container } = render(<KevBadge pastDue ransomware />)
    const el = container.firstElementChild as HTMLElement
    expect(el.getAttribute('data-slot')).toBe('kev-badge')
    expect(el.getAttribute('data-past-due')).toBe('true')
    expect(el.getAttribute('data-ransomware')).toBe('true')
    expect(el.className).toContain('text-destructive')
    expect(screen.getByText('KEV')).toBeTruthy()
    expect(el.getAttribute('aria-label')).toBe('KEV, ransomware, past due')
    expect(el.getAttribute('data-segmented')).toBe('true')
    const q = el.querySelector('[data-slot="signal-chip-qualifier"]') as HTMLElement
    expect(q.className).toContain('border-l')
    expect(screen.getByText('Past due')).toBeTruthy()
    expect(screen.getByText('Ransomware')).toBeTruthy()
    expect(el.textContent).not.toMatch(/[·•∙│|]/)
  })

  it('KevBadge on time is neutral text with a red bolt', () => {
    const { container } = render(<KevBadge label="KEV 3" />)
    expect(container.firstElementChild?.className).not.toContain('text-destructive')
    expect(container.querySelector('svg')?.getAttribute('class')).toContain('text-sig-icon')
    expect(screen.getByText('KEV 3')).toBeTruthy()
    expect(container.querySelector('[data-slot="signal-chip-qualifier"]')).toBeNull()
  })

  it('EpssChip keeps threshold, label and neutral colour', () => {
    const { container, rerender } = render(<EpssChip score={0.97} />)
    const el = container.firstElementChild as HTMLElement
    expect(el.getAttribute('data-slot')).toBe('epss-chip')
    expect(el.getAttribute('aria-label')).toBe('EPSS 97%')
    expect(el.className).not.toMatch(/text-(destructive|warning|sev)/)
    rerender(<EpssChip score={0.05} />)
    expect(container.firstElementChild).toBeNull()
    rerender(<EpssChip score={0.05} threshold={0} />)
    expect(container.firstElementChild).not.toBeNull()
  })
})

describe('DueChip', () => {
  const now = new Date('2026-10-23T12:00:00Z')
  it('counts whole days ahead, neutral', () => {
    const { container } = render(<DueChip dueAt="2026-10-26T18:00:00Z" now={now} />)
    expect(screen.getByText('Due in 3 d')).toBeTruthy()
    expect(container.firstElementChild?.getAttribute('data-tone')).toBe('neutral')
  })
  it('says today inside the day', () => {
    render(<DueChip dueAt="2026-10-23T20:00:00Z" now={now} />)
    expect(screen.getByText('Due today')).toBeTruthy()
  })
  it('turns alert, with red text, when overdue', () => {
    const { container } = render(<DueChip dueAt="2026-10-19T11:00:00Z" now={now} />)
    expect(screen.getByText('Overdue 4 d')).toBeTruthy()
    const el = container.firstElementChild as HTMLElement
    expect(el.getAttribute('data-overdue')).toBe('true')
    expect(el.className).toContain('text-destructive')
  })
  it('renders nothing without a valid date', () => {
    const { container, rerender } = render(<DueChip dueAt={null} />)
    expect(container.firstElementChild).toBeNull()
    rerender(<DueChip dueAt="not a date" />)
    expect(container.firstElementChild).toBeNull()
  })
})

describe('Tag', () => {
  it('is a neutral pill with ink text', () => {
    const { container } = render(<Tag label="Linux" />)
    const el = container.firstElementChild as HTMLElement
    expect(el.getAttribute('data-variant')).toBe('default')
    expect(el.className).toContain('rounded-full')
    expect(el.className).toContain('text-foreground')
    expect(el.className).toContain('max-w-[200px]')
    expect(el.className).not.toMatch(/uppercase|font-mono|text-\[(9|10|11)px\]/)
    expect(el.getAttribute('title')).toBe('Linux')
  })

  it('plain has no border or fill', () => {
    const { container } = render(<Tag label="Host" variant="plain" icon={Globe} />)
    const el = container.firstElementChild as HTMLElement
    expect(el.getAttribute('data-variant')).toBe('plain')
    expect(el.className).not.toContain('border')
    expect(el.querySelector('svg')).toBeTruthy()
  })

  it('scoped renders the key and the value as two parts, no separator glyph', () => {
    const { container } = render(<Tag scope="env" label="production" />)
    expect(container.firstElementChild?.getAttribute('data-variant')).toBe('scoped')
    expect(screen.getByText('env')).toBeTruthy()
    expect(screen.getByText('production')).toBeTruthy()
    expect(container.textContent).not.toMatch(/[·•∙]/)
  })

  it.each(TAG_PALETTE)('swatch %s is an 8px dot and the text stays ink', (name) => {
    const { container } = render(<Tag label="pci" swatch={name} />)
    const dot = container.querySelector('[data-slot="tag-swatch"]') as HTMLElement
    expect(dot.className).toContain(TAG_SWATCH_CLASS[name])
    expect(dot.className).toContain('size-2')
    expect(dot.getAttribute('aria-hidden')).toBe('true')
    expect(container.firstElementChild?.className).toContain('text-foreground')
    expect(container.firstElementChild?.className).not.toContain(`text-tag-${name}`)
  })

  it('ignores a swatch outside the palette (never a free CSS string)', () => {
    const { container } = render(<Tag label="x" swatch="teal" />)
    expect(container.querySelector('[data-slot="tag-swatch"]')).toBeNull()
    expect(isTagPaletteName('teal')).toBe(false)
    expect(isTagPaletteName('url(javascript:x)')).toBe(false)
    expect(TAG_PALETTE as readonly string[]).not.toContain('teal')
  })

  it('level draws four bars, filled up to the level, and bolds the top level', () => {
    const { container } = render(<Tag label="Critical" level={4} />)
    const rects = [...container.querySelectorAll('svg rect')]
    expect(rects).toHaveLength(4)
    expect(rects.filter((r) => r.getAttribute('opacity') === '1')).toHaveLength(4)
    expect(screen.getByText('Critical').className).toContain('font-bold')
    const low = render(<Tag label="Low" level={1} />)
    expect(
      [...low.container.querySelectorAll('svg rect')].filter(
        (r) => r.getAttribute('opacity') === '1'
      )
    ).toHaveLength(1)
    expect(screen.getByText('Low').className).not.toContain('font-bold')
  })

  it('onRemove shows a named button that calls back', () => {
    const onRemove = vi.fn()
    render(<Tag label="legacy" onRemove={onRemove} />)
    fireEvent.click(screen.getByRole('button', { name: 'Remove legacy' }))
    expect(onRemove).toHaveBeenCalledTimes(1)
  })
})

describe('Counter', () => {
  it('is a neutral number with a full screen-reader name', () => {
    const { container } = render(<Counter value={12} />)
    const el = container.firstElementChild as HTMLElement
    expect(el.getAttribute('aria-label')).toBe('12 items')
    expect(el.textContent).toBe('12')
    expect(el.className).toContain('bg-ctr-bg')
    expect(el.className).toContain('tabular-nums')
    expect(el.className).not.toContain('bg-ctr-em-bg')
  })
  it('caps at 99+, keeping the real number for assistive tech', () => {
    const { container } = render(<Counter value={1200} />)
    expect(container.textContent).toBe('99+')
    expect(container.firstElementChild?.getAttribute('aria-label')).toBe('1200 items')
  })
  it('honours max', () => {
    const { container } = render(<Counter value={11} max={9} />)
    expect(container.textContent).toBe('9+')
  })
  it('emphasis is the ink fill', () => {
    const { container } = render(<Counter value={5} emphasis />)
    expect(container.firstElementChild?.className).toContain('bg-ctr-em-bg')
    expect(container.firstElementChild?.getAttribute('data-emphasis')).toBe('true')
  })
  it('renders nothing for a non-number', () => {
    const { container } = render(<Counter value={Number.NaN} />)
    expect(container.firstElementChild).toBeNull()
  })
})

describe('Marker', () => {
  const WORD: Record<string, string> = {
    beta: 'Beta',
    preview: 'Preview',
    new: 'New',
    soon: 'Soon',
    enterprise: 'Enterprise',
    adminOnly: 'Admin only',
    system: 'System',
  }
  it.each(MARKER_KINDS)('%s is an outline box with its word and no hue', (kind) => {
    const { container } = render(<Marker kind={kind} />)
    const el = container.firstElementChild as HTMLElement
    expect(el.textContent).toBe(WORD[kind])
    expect(el.className).toContain('border')
    expect(el.className).not.toMatch(/\bbg-|text-(success|warning|destructive|info|signal)/)
    expect(el.className).not.toMatch(/uppercase|text-\[(9|10|11)px\]/)
  })
  it('locks for admin-only and system, gems for enterprise', () => {
    expect(render(<Marker kind="adminOnly" />).container.querySelector('svg')).toBeTruthy()
    expect(render(<Marker kind="beta" />).container.querySelector('svg')).toBeNull()
  })
})

describe('SeverityBadge score', () => {
  it.each([
    [92, 'critical', 'Critical'],
    [71, 'high', 'High'],
    [48, 'medium', 'Medium'],
    [23, 'low', 'Low'],
    [6, 'info', 'Minimal'],
    [0, 'info', 'No open risk'],
  ])('score %s uses the %s glyph and names its band', (score, level, band) => {
    const { container } = render(<SeverityBadge score={score} />)
    const el = container.firstElementChild as HTMLElement
    expect(el.getAttribute('data-severity')).toBe(level)
    expect(el.getAttribute('data-score')).toBe(String(score))
    expect(el.textContent).toBe(String(score))
    expect(el.getAttribute('aria-label')).toBe(`${score}, ${band}`)
    expect(el.querySelector('svg')).toBeTruthy()
  })
  it('takes the accessible name and tooltip from its caller', () => {
    const { container } = render(<SeverityBadge score={92} aria-label="Risk 92" title="Risk 92" />)
    const el = container.firstElementChild as HTMLElement
    expect(el.textContent).toBe('92')
    expect(el.getAttribute('aria-label')).toBe('Risk 92')
    expect(el.getAttribute('title')).toBe('Risk 92')
  })
  it('keeps the severity form unchanged', () => {
    const { container } = render(<SeverityBadge severity="high" />)
    expect(container.textContent).toBe('High')
    expect(container.firstElementChild?.getAttribute('aria-label')).toBeNull()
  })
})

describe('StatusLozenge waiting tone', () => {
  it('uses the waiting tokens', () => {
    const { container } = render(<StatusLozenge tone="waiting" label="Waiting for approval" />)
    const el = container.firstElementChild as HTMLElement
    expect(el.getAttribute('data-tone')).toBe('waiting')
    expect(el.className).toContain('bg-st-waiting-bg')
    expect(el.className).toContain('text-st-waiting-fg')
  })
})
