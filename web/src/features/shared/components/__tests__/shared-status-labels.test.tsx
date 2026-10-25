import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { TonePill, PILL_TONE_STATE, type PillTone } from '../tone-pill'
import { RunStatusBadge } from '../run-status-badge'
import { StatusBadge } from '../status-badge'
import { SensorTag } from '@/features/sensors/components/sensor-cells'
import { FactChip, type FactChipTone } from '@/features/assets/components/service-cells/fact-chip'
import { PendingSetupBadge } from '../one-time-setup-link'

/** Nothing in a label may spin or pulse, and none may use a /15 tint. */
function expectCalm(root: Element) {
  expect(root.outerHTML).not.toMatch(/animate-(spin|ping|pulse)/)
  expect(root.outerHTML).not.toMatch(/\/15\b/)
  expect(root.outerHTML).not.toMatch(/text-\[(9|10|11)(\.\d+)?px\]/)
}

describe('TonePill is a HealthStatus', () => {
  const MAP: Record<PillTone, string> = {
    success: 'ok',
    warning: 'warn',
    destructive: 'down',
    info: 'run',
    muted: 'off',
  }
  it.each(Object.entries(MAP))('%s renders the %s state', (tone, state) => {
    const { container } = render(<TonePill tone={tone as PillTone} label="Label" state="raw" />)
    const el = container.querySelector('[data-slot="health-status"]') as HTMLElement
    expect(PILL_TONE_STATE[tone as PillTone]).toBe(state)
    expect(el.getAttribute('data-health')).toBe(state)
    expect(el.getAttribute('data-state')).toBe('raw')
    expect(el.querySelector('svg')).toBeTruthy()
    // The text is foreground (or quiet), never the tint colour: AA by construction.
    expect(el.className).not.toMatch(/text-(success|warning|info|destructive)\b/)
    expectCalm(container)
  })

  it('keeps a muted detail line under the state', () => {
    render(<TonePill tone="success" label="Online" detail="heartbeat 4s ago" />)
    expect(screen.getByText('heartbeat 4s ago').className).toContain('text-muted-foreground')
  })

  it('accepts a node as the label and passes the tooltip', () => {
    render(<TonePill tone="warning" label={<b>Degraded</b>} title="Late heartbeat" />)
    expect(screen.getByText('Degraded')).toBeTruthy()
    expect(document.querySelector('[title="Late heartbeat"]')).toBeTruthy()
  })
})

describe('RunStatusBadge is a HealthStatus', () => {
  const CASES: Array<[string, string, string]> = [
    ['queued', 'queued', 'Queued'],
    ['pending', 'queued', 'Pending'],
    ['running', 'run', 'Running'],
    ['completed', 'ok', 'Completed'],
    ['partial', 'warn', 'Partial'],
    ['failed', 'down', 'Failed'],
    ['timeout', 'warn', 'Timed out'],
    ['canceled', 'off', 'Canceled'],
    ['cancelled', 'off', 'Canceled'],
    ['blocked', 'paused', 'Blocked'],
  ]
  it.each(CASES)('%s is the %s state reading "%s", static', (status, state, word) => {
    const { container } = render(<RunStatusBadge status={status} />)
    const el = container.querySelector('[data-slot="health-status"]') as HTMLElement
    expect(el.getAttribute('data-health')).toBe(state)
    expect(screen.getByText(word)).toBeTruthy()
    expectCalm(container)
  })

  it('adds progress and a note as separate muted parts', () => {
    const { container } = render(
      <RunStatusBadge status="running" progress={42.4} note="3 unreachable" />
    )
    expect(screen.getByText('42%')).toBeTruthy()
    expect(screen.getByText('3 unreachable')).toBeTruthy()
    expect(container.textContent).not.toMatch(/[·•∙]/)
  })

  it('ignores progress for a finished run', () => {
    render(<RunStatusBadge status="completed" progress={100} />)
    expect(screen.queryByText('100%')).toBeNull()
  })

  it('shows an unknown status humanized in the unknown state, and a label override', () => {
    const { container, rerender } = render(<RunStatusBadge status="paused_by_admin" />)
    expect(container.querySelector('[data-health="unknown"]')).toBeTruthy()
    expect(screen.getByText(/paused/i)).toBeTruthy()
    rerender(<RunStatusBadge status="running" label="Waiting for a sensor" />)
    expect(screen.getByText('Waiting for a sensor')).toBeTruthy()
  })
})

describe('shared StatusBadge', () => {
  it.each([
    ['active', 'ok', 'Active'],
    ['stale', 'warn', 'Stale'],
    ['inactive', 'off', 'Inactive'],
    ['pending', 'queued', 'Pending'],
    ['failed', 'down', 'Failed'],
  ] as const)('%s reads %s', (status, state, word) => {
    const { container } = render(<StatusBadge status={status} />)
    expect(container.querySelector(`[data-health="${state}"]`)).toBeTruthy()
    expect(screen.getByText(word)).toBeTruthy()
  })
})

describe('SensorTag', () => {
  it('classification tones are a neutral Tag', () => {
    for (const tone of ['muted', 'info'] as const) {
      const { container, unmount } = render(<SensorTag tone={tone}>update</SensorTag>)
      expect(container.querySelector('[data-slot="tag"]')).toBeTruthy()
      expectCalm(container)
      unmount()
    }
  })
  it.each([
    ['warning', 'warn'],
    ['destructive', 'down'],
    ['success', 'ok'],
  ] as const)('%s tone is the %s health state', (tone, state) => {
    const { container } = render(<SensorTag tone={tone}>needs attention</SensorTag>)
    expect(container.querySelector(`[data-health="${state}"]`)).toBeTruthy()
    expectCalm(container)
  })
})

describe('FactChip tones', () => {
  const TONES: FactChipTone[] = [
    'neutral',
    'muted',
    'label',
    'success',
    'info',
    'warning',
    'destructive',
  ]
  it.each(TONES)('%s uses no /15 tint and no tiny text', (tone) => {
    const { container } = render(<FactChip tone={tone}>fact</FactChip>)
    expectCalm(container)
  })
  it('maps status tones to the attention tones (research/266)', () => {
    const cls = (tone: FactChipTone) =>
      render(<FactChip tone={tone}>x</FactChip>).container.firstElementChild?.className ?? ''
    expect(cls('success')).toContain('bg-st-resolved-bg')
    expect(cls('info')).toContain('bg-st-progress-bg')
    expect(cls('warning')).toContain('bg-st-accepted-bg')
    expect(cls('destructive')).toContain('bg-tone-danger-bg')
    expect(cls('destructive')).toContain('text-tone-danger-fg')
  })
})

describe('PendingSetupBadge', () => {
  it('is a waiting lozenge', () => {
    const { container } = render(<PendingSetupBadge />)
    expect(screen.getByText('Pending setup')).toBeTruthy()
    expect(container.querySelector('[data-tone="waiting"]')).toBeTruthy()
  })
})

describe('repository workspace labels (the object-in-cn bug)', () => {
  it(
    'branch status renders a coloured health icon, not an empty class',
    { timeout: 30000 },
    async () => {
      const { BranchStatusBadge } =
        await import('@/features/repositories/components/repository-workspace')
      const states = {
        passed: 'ok',
        failed: 'down',
        warning: 'warn',
        scanning: 'run',
        not_scanned: 'off',
      }
      for (const [status, state] of Object.entries(states)) {
        const { container, unmount } = render(<BranchStatusBadge status={status as 'passed'} />)
        const el = container.querySelector('[data-slot="health-status"]') as HTMLElement
        expect(el.getAttribute('data-health')).toBe(state)
        expect(el.querySelector('svg')?.getAttribute('class')).toContain(`text-hl-`)
        expect(container.innerHTML).not.toContain('[object Object]')
        expectCalm(container)
        unmount()
      }
    }
  )

  it('triage status renders a tinted lozenge', async () => {
    const { TriageStatusBadge } =
      await import('@/features/repositories/components/repository-workspace')
    const tones = { needs_triage: 'triage', triaged: 'open', escalated: 'waiting' }
    for (const [status, tone] of Object.entries(tones)) {
      const { container, unmount } = render(<TriageStatusBadge status={status as 'triaged'} />)
      const el = container.querySelector('[data-slot="status-lozenge"]') as HTMLElement
      expect(el.getAttribute('data-tone')).toBe(tone)
      expect(el.className).toContain(`bg-st-${tone}-bg`)
      expect(container.innerHTML).not.toContain('[object Object]')
      unmount()
    }
  })
})
