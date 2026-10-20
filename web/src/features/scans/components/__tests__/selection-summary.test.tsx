import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

let results: Array<{ target: string; allowed: boolean; code?: string }> = []
vi.mock('@/features/scope', () => ({
  ScopeCheckList: () => null,
  useScopeCheck: () => ({ available: true, isLoading: false, results }),
}))
vi.mock('@/hooks/use-debounce', () => ({ useDebounce: (v: string) => v }))

import { SelectionSummary } from '../target-picker/selection-summary'

const base = { chips: [], groupCount: 0, invalidCount: 0 }

describe('SelectionSummary', () => {
  it('counts only targets the gate lets through, and a name with no DNS answer on its own', () => {
    results = [
      { target: 'a.example.com', allowed: true },
      { target: 'gone.example.com', allowed: false, code: 'unresolved' },
      { target: '10.1.1.1', allowed: false, code: 'zone_none' },
    ]
    render(
      <SelectionSummary {...base} targets={['a.example.com', 'gone.example.com', '10.1.1.1']} />
    )
    expect(screen.getByText(/1 can be scanned/)).toBeInTheDocument()
    expect(screen.getByText('1 may not be scanned')).toBeInTheDocument()
    expect(screen.getByText('1 do not resolve in DNS')).toBeInTheDocument()
    expect(screen.queryByText(/in scope/)).toBeNull()
  })
})
