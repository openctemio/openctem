import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

let results: Array<{ target: string; allowed: boolean; code?: string }> = []
let available = true
const recheck = vi.fn(async () => undefined)
vi.mock('@/features/scope', () => ({
  ScopeCheckList: () => <div data-testid="scope-check-list" />,
  useScopeCheck: () => ({
    available,
    isLoading: false,
    results,
    resultFor: (target: string) =>
      results.find((r) => r.target.toLowerCase() === target.trim().toLowerCase()),
    recheck,
  }),
}))
vi.mock('@/hooks/use-debounce', () => ({ useDebounce: (v: string) => v }))

import {
  scanReadiness,
  SelectionSummary,
  type ScanReadiness,
} from '../target-picker/selection-summary'

const base = { chips: [], groupCount: 0, invalidCount: 0 }

beforeEach(() => {
  available = true
  recheck.mockClear()
})

describe('SelectionSummary', () => {
  it('counts only targets the gate lets through, and a name with no DNS answer on its own', () => {
    results = [
      { target: 'a.example.com', allowed: true },
      { target: 'gone.example.com', allowed: false, code: 'unresolved' },
      { target: '10.1.1.1', allowed: false, code: 'zone_none' },
    ]
    const { container } = render(
      <SelectionSummary {...base} targets={['a.example.com', 'gone.example.com', '10.1.1.1']} />
    )
    expect(screen.getByText(/1 can be scanned/)).toBeInTheDocument()
    expect(screen.getByText('1 may not be scanned')).toBeInTheDocument()
    expect(screen.getByText('1 does not resolve in DNS')).toBeInTheDocument()
    expect(screen.queryByText(/in scope/)).toBeNull()
    // Separate elements, never a middle-dot separator.
    expect(container.textContent).not.toContain('·')
  })

  it('every target unresolved: says nothing to scan, offers Check DNS again, reports blocked', async () => {
    results = [{ target: 'go.example.com', allowed: false, code: 'unresolved' }]
    const onReadiness = vi.fn()
    const { container } = render(
      <SelectionSummary {...base} targets={['go.example.com']} onReadinessChange={onReadiness} />
    )
    expect(
      screen.getByText('Nothing to scan: go.example.com does not resolve in DNS.')
    ).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/zone/i)
    await waitFor(() =>
      expect(onReadiness).toHaveBeenLastCalledWith(
        expect.objectContaining({ state: 'blocked', scannable: 0, unresolved: ['go.example.com'] })
      )
    )
    fireEvent.click(screen.getByRole('button', { name: /Check DNS again/ }))
    await waitFor(() => expect(recheck).toHaveBeenCalledTimes(1))
  })

  it('every target refused for other reasons: lists them with their fixes, reports blocked', async () => {
    results = [{ target: '10.1.1.1', allowed: false, code: 'zone_none' }]
    const onReadiness = vi.fn()
    render(<SelectionSummary {...base} targets={['10.1.1.1']} onReadinessChange={onReadiness} />)
    expect(screen.getByText(/None of these targets can be scanned yet/)).toBeInTheDocument()
    expect(screen.getByTestId('scope-check-list')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Check DNS again/ })).toBeNull()
    await waitFor(() =>
      expect(onReadiness).toHaveBeenLastCalledWith(expect.objectContaining({ state: 'blocked' }))
    )
  })

  it('some targets unscannable: says the scan runs on the rest, reports partial', async () => {
    results = [
      { target: 'a.example.com', allowed: true },
      { target: 'go.example.com', allowed: false, code: 'unresolved' },
    ]
    const onReadiness = vi.fn()
    render(
      <SelectionSummary
        {...base}
        targets={['a.example.com', 'go.example.com']}
        onReadinessChange={onReadiness}
      />
    )
    expect(
      screen.getByText(
        'The scan runs on the 1 targets that can be scanned and leaves out the other 1.'
      )
    ).toBeInTheDocument()
    expect(screen.queryByText(/Nothing to scan/)).toBeNull()
    await waitFor(() =>
      expect(onReadiness).toHaveBeenLastCalledWith(
        expect.objectContaining({ state: 'partial', scannable: 1 })
      )
    )
  })

  it('without the scope permission the readiness stays unknown (the server decides)', async () => {
    available = false
    results = [{ target: 'go.example.com', allowed: false, code: 'unresolved' }]
    const onReadiness = vi.fn()
    render(
      <SelectionSummary {...base} targets={['go.example.com']} onReadinessChange={onReadiness} />
    )
    await waitFor(() =>
      expect(onReadiness).toHaveBeenLastCalledWith(expect.objectContaining({ state: 'unknown' }))
    )
    expect(screen.queryByText(/Nothing to scan/)).toBeNull()
  })
})

describe('scanReadiness', () => {
  const lookup =
    (rs: Array<{ target: string; allowed: boolean; code?: string }>) => (target: string) =>
      rs.find((r) => r.target === target)

  it('is unknown while a target has no answer yet (an answer about an older selection)', () => {
    const r: ScanReadiness = scanReadiness(
      ['a.example.com', 'b.example.com'],
      lookup([{ target: 'a.example.com', allowed: false, code: 'unresolved' }])
    )
    expect(r.state).toBe('unknown')
  })

  it('never blocks when asset groups are selected (members are checked when the scan runs)', () => {
    const r = scanReadiness(
      ['go.example.com'],
      lookup([{ target: 'go.example.com', allowed: false, code: 'unresolved' }]),
      1
    )
    expect(r.state).toBe('unknown')
  })

  it('is ready when all can be scanned', () => {
    expect(
      scanReadiness(['a.example.com'], lookup([{ target: 'a.example.com', allowed: true }])).state
    ).toBe('ready')
  })
})
