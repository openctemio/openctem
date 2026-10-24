import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import type { ScanConfig } from '@/lib/api/scan-types'
import { IntensityBadge } from '../intensity-badge'
import { ScanMobileCard } from '../scan-mobile-card'

const at = '2026-10-20T10:00:00Z'

function config(over: Partial<ScanConfig> = {}): ScanConfig {
  return {
    id: 's1',
    name: 'Daily external recon',
    scan_type: 'single',
    scanner_name: 'nuclei',
    intensity: 'intrusive',
    total_runs: 30,
    successful_runs: 0,
    failed_runs: 13,
    partial_runs: 3,
    blocked_runs: 14,
    last_run: {
      id: 'r30',
      status: 'blocked',
      created_at: at,
      refusal_code: 'ALL_TARGETS_UNCONFIRMED',
    },
    recent_runs: [
      { id: 'r30', status: 'blocked', created_at: at },
      { id: 'r29', status: 'partial', created_at: at },
      { id: 'r28', status: 'partial', created_at: at },
      { id: 'r27', status: 'failed', created_at: at },
    ],
    ...over,
  } as ScanConfig
}

const selection = { selectable: true, selected: false, onSelectedChange: vi.fn() }

describe('ScanMobileCard', () => {
  it('puts each fact in its own element: state, type, kind, intensity, runs, history, why blocked', () => {
    render(
      <ScanMobileCard
        config={config()}
        selection={selection}
        actions={<button type="button">menu</button>}
        onOpen={vi.fn()}
        onOpenRun={vi.fn()}
      />
    )
    expect(screen.getByText('Daily external recon')).toBeInTheDocument()
    expect(screen.getByText('Blocked')).toBeInTheDocument()
    expect(screen.getByText('nuclei')).toBeInTheDocument()
    expect(screen.getByText('Single check')).toBeInTheDocument()
    expect(screen.getByText('Intrusive (full)')).toBeInTheDocument()
    expect(screen.getByText('30 runs')).toBeInTheDocument()
    // 2 partial + 1 failed counted: 67%; partial runs are not failures.
    expect(screen.getByRole('img', { name: /Success rate 67%/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Review scope' })).toBeInTheDocument()
    // No middot separators anywhere on the card.
    expect(document.body.textContent).not.toContain('·')
  })

  it('opens the scan on a tap, the run from its state, and selects from the checkbox', () => {
    const onOpen = vi.fn()
    const onOpenRun = vi.fn()
    const onSelectedChange = vi.fn()
    render(
      <ScanMobileCard
        config={config()}
        selection={{ ...selection, onSelectedChange }}
        actions={null}
        onOpen={onOpen}
        onOpenRun={onOpenRun}
      />
    )
    fireEvent.click(screen.getByText('nuclei'))
    expect(onOpen).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: /Open the latest run/ }))
    expect(onOpenRun).toHaveBeenCalledWith('r30')
    expect(onOpen).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select Daily external recon' }))
    expect(onSelectedChange).toHaveBeenCalledWith(true)
    expect(onOpen).toHaveBeenCalledTimes(1)
  })

  it('reads Never and no history for a scan that never ran', () => {
    render(
      <ScanMobileCard
        config={config({ total_runs: 0, last_run: undefined, recent_runs: undefined })}
        selection={selection}
        actions={null}
        onOpen={vi.fn()}
        onOpenRun={vi.fn()}
      />
    )
    expect(screen.getByText('Never')).toBeInTheDocument()
    expect(screen.getByText('0 runs')).toBeInTheDocument()
    expect(screen.queryByRole('img', { name: /Success rate/ })).toBeNull()
  })
})

describe('IntensityBadge', () => {
  it('shows intrusive as a neutral signal chip and active as a plain tag, never a coloured badge', () => {
    const { rerender, container } = render(<IntensityBadge intensity="intrusive" />)
    const chip = container.querySelector('[data-slot="signal-chip"]')
    expect(chip).not.toBeNull()
    expect(chip?.className).not.toMatch(/text-warning|text-orange|bg-orange/)
    rerender(<IntensityBadge intensity="active" />)
    expect(container.querySelector('[data-slot="tag"]')).not.toBeNull()
    expect(container.querySelector('[data-slot="tag"]')?.className).not.toMatch(/text-info/)
  })
})
