import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import type { ScanRun } from '@/lib/api/scan-workflow-types'
import { SCAN_RUN_STATUSES } from '@/lib/api/scan-workflow-types'
import { RUN_STATUSES, scanRunFixtures } from '../../../../../e2e/helpers/scan-run-fixtures'
import { ScanRunMobileCard } from '../scan-run-mobile-card'

const noSelection = { selectable: false, selected: false, onSelectedChange: vi.fn() }
const runs = scanRunFixtures() as unknown as ScanRun[]

function renderCard(run: ScanRun, onOpen = vi.fn()) {
  return render(<ScanRunMobileCard run={run} selection={noSelection} onOpen={onOpen} />)
}

describe('ScanRunMobileCard', () => {
  it('the fixtures cover every run status the API stores', () => {
    expect([...RUN_STATUSES].sort()).toEqual([...SCAN_RUN_STATUSES].sort())
    for (const status of SCAN_RUN_STATUSES) {
      expect(runs.some((r) => r.status === status)).toBe(true)
    }
  })

  it.each(runs.map((r, i) => [i, r.status, r] as const))(
    'run %i (%s): names its state, in fixed slots, with no label/value grid',
    (_, __, run) => {
      const { container } = renderCard(run)
      const state = container.querySelector('[data-slot="run-state"] [data-slot="health-status"]')
      expect(state?.textContent?.trim()).toBeTruthy()
      // The state chip never shrinks or wraps; the reason is one cut line.
      expect(state?.className).toContain('shrink-0')
      expect(state?.className).toContain('whitespace-nowrap')
      const reason = container.querySelector('[data-slot="run-status-more"]')
      if (reason) expect(reason.className).toMatch(/\btruncate\b/)
      expect(container.querySelector('dl, dt, dd')).toBeNull()
      expect(container.textContent).not.toContain('·')
    }
  )

  it('shows the partial run of the report on four lines: name, state + reason, tasks, origin + time', () => {
    const { container } = renderCard(runs[0])
    expect(container.querySelector('[data-slot="run-card-title"]')?.textContent).toContain(
      'External perimeter recon'
    )
    const stateLine = container.querySelector('[data-slot="run-state"]')!
    expect(stateLine.textContent).toContain('Partial')
    expect(stateLine.textContent).toContain('Probing')
    expect(stateLine.textContent).toContain('2 of 6 steps did not finish')
    expect(stateLine.getAttribute('title')).toContain('Scan run completed partially')
    const lines = container.querySelectorAll('[data-slot="meta-line"]')
    expect(lines).toHaveLength(2)
    expect(lines[0].textContent).toContain('4/6')
    expect(lines[0].textContent).toContain('2 failed')
    expect(lines[0].textContent).toContain('3 findings')
    expect(lines[1].textContent).toContain('Ana Example')
    expect(lines[1].querySelector('time')).not.toBeNull()
  })

  it('opens the run on a tap, but not on a link inside it', () => {
    const onOpen = vi.fn()
    const { container } = renderCard(runs[0], onOpen)
    fireEvent.click(container.querySelector('[data-slot="run-card"]')!)
    expect(onOpen).toHaveBeenCalledWith(runs[0])
    onOpen.mockClear()
    fireEvent.click(screen.getByRole('link', { name: /External perimeter recon/ }))
    expect(onOpen).not.toHaveBeenCalled()
  })

  it('names a retest, a deleted scan and a run without a scan', () => {
    const retest = renderCard(runs.find((r) => r.kind === 'retest')!)
    expect(retest.getByText(/retest/i)).toBeInTheDocument()
    retest.unmount()
    const deleted = renderCard(runs.find((r) => r.scan_id && r.scan_name === '')!)
    expect(deleted.getByText('Deleted scan')).toBeInTheDocument()
    deleted.unmount()
    const none = renderCard(runs.find((r) => !r.scan_id && r.kind === 'scan')!)
    expect(none.container.querySelector('[data-slot="run-card-title"]')?.textContent).toBeTruthy()
  })
})
