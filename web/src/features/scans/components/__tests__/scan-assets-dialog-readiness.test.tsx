import { describe, expect, it, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import type { ScanReadiness } from '../target-picker/selection-summary'

// The selection summary decides readiness from the scope check (its own
// tests); here it reports what the test asks, and the dialog must follow.
let report: ((r: ScanReadiness) => void) | undefined
vi.mock('../target-picker/selection-summary', () => ({
  SelectionSummary: ({ onReadinessChange }: { onReadinessChange?: (r: ScanReadiness) => void }) => {
    report = onReadinessChange
    return null
  },
}))
vi.mock('../scanner-select', async () => {
  const React = await import('react')
  return {
    // A scanner is already chosen: only readiness decides the button.
    ScannerSelect: ({ onChange }: { onChange: (v: string) => void }) => {
      React.useEffect(() => onChange('nuclei'), [onChange])
      return null
    },
  }
})
vi.mock('@/lib/api/scan-workflow-hooks', () => ({
  useQuickScan: () => ({ trigger: vi.fn() }),
  invalidateScanRunsCache: vi.fn(),
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { ScanAssetsDialog } from '../scan-assets-dialog'

const candidates = [{ id: 'a1', label: 'go.example.com', target: 'go.example.com' }]

describe('ScanAssetsDialog start button follows the preflight', () => {
  it('is disabled when nothing can be scanned and enabled again when something can', async () => {
    render(<ScanAssetsDialog open onOpenChange={vi.fn()} candidates={candidates} />)
    const start = screen.getByRole('button', { name: /Start Scan/ })
    expect(start).toBeEnabled()

    await act(async () =>
      report?.({ state: 'blocked', scannable: 0, unresolved: ['go.example.com'], refused: 0 })
    )
    expect(start).toBeDisabled()

    await act(async () => report?.({ state: 'partial', scannable: 1, unresolved: [], refused: 1 }))
    expect(start).toBeEnabled()

    await act(async () => report?.({ state: 'unknown', scannable: 0, unresolved: [], refused: 0 }))
    expect(start).toBeEnabled() // no answer: the server decides
  })
})
