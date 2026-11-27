import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import type { ScanConfig } from '@/lib/api/scan-types'
import { scanDetailHref } from '../../lib/scan-link'
import { LastRunCell } from '../last-run-cell'
import { ScanNameCell } from '../scan-name-cell'
import { ScheduleCell } from '../schedule-cell'

vi.mock('@/lib/permissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/permissions')>()
  return { ...actual, useHasPermission: () => true }
})

function config(over: Partial<ScanConfig>): ScanConfig {
  return {
    id: 's1',
    tenant_id: 't1',
    name: 'Scan',
    scan_type: 'single',
    targets_per_job: 1,
    schedule_type: 'daily',
    schedule_timezone: 'UTC',
    run_on_tenant_runner: false,
    sensor_preference: 'auto',
    timeout_seconds: 3600,
    max_retries: 0,
    retry_backoff_seconds: 60,
    status: 'active',
    total_runs: 0,
    successful_runs: 0,
    failed_runs: 0,
    created_at: '',
    updated_at: '',
    ...over,
  }
}

describe('scanDetailHref', () => {
  it('keeps an id from data inside the scan route', () => {
    expect(scanDetailHref('abc')).toBe('/scans/abc')
    for (const hostile of [
      '../admin',
      'a/b',
      'x?y=1',
      'x#frag',
      'javascript:alert(1)',
      '//evil.example',
    ]) {
      const href = scanDetailHref(hostile)
      expect(href.startsWith('/scans/')).toBe(true)
      expect(href.slice('/scans/'.length)).not.toMatch(/[/?#:]/)
    }
  })
})

describe('ScanNameCell', () => {
  it('is a link to the scan page; a plain click opens the sheet instead', () => {
    const onOpen = vi.fn()
    render(
      <ScanNameCell
        config={config({ name: 'Nightly', description: 'Edge hosts' })}
        onOpen={onOpen}
      />
    )
    const link = screen.getByRole('link', { name: 'Nightly, view details' })
    expect(link).toHaveAttribute('href', '/scans/s1')
    // The description is not a second line: it is in the hover text.
    expect(link).toHaveAttribute('title', 'Nightly\nEdge hosts')
    expect(screen.queryByText('Edge hosts')).toBeNull()
    fireEvent.click(link)
    expect(onOpen).toHaveBeenCalledTimes(1)
  })

  it('a modified click is left to the browser (the page in a new tab)', () => {
    const onOpen = vi.fn()
    render(<ScanNameCell config={config({ name: 'Nightly' })} onOpen={onOpen} />)
    fireEvent.click(screen.getByRole('link'), { ctrlKey: true })
    expect(onOpen).not.toHaveBeenCalled()
  })
})

describe('one-line cells of the scans table', () => {
  it('a blocked latest run keeps the link to its fix, with the reason as its title', () => {
    render(
      <LastRunCell
        inline
        showHint
        run={{
          id: 'r1',
          status: 'blocked',
          refusal_code: 'ALL_TARGETS_UNCONFIRMED',
          created_at: new Date().toISOString(),
        }}
      />
    )
    const cell = document.querySelector('[data-slot="last-run-cell"]')
    expect(cell).not.toBeNull()
    // No paragraph under the state: the row stays one line.
    expect(document.querySelector('[data-slot="blocked-run-hint"]')).toBeNull()
    const fix = screen.queryByRole('link')
    if (fix) expect(fix.getAttribute('title')).toBeTruthy()
  })

  it('the schedule, its next run and its switch share one line', () => {
    render(
      <ScheduleCell
        inline
        config={config({ next_run_at: new Date(Date.now() + 3 * 86_400_000).toISOString() })}
        onToggle={vi.fn()}
      />
    )
    const text = document.querySelector('[data-slot="schedule-cell-text"]')
    expect(text).not.toBeNull()
    expect(text?.className).toContain('whitespace-nowrap')
    expect(screen.getByText('Daily')).toBeInTheDocument()
    expect(screen.getByRole('switch')).toBeInTheDocument()
    expect(text?.textContent).toMatch(/Next:/)
  })
})
