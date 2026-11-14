import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('@/lib/error-reporting', () => ({ reportRouteError: vi.fn() }))
vi.mock('@/features/shared/components/report-problem', () => ({ ReportProblem: () => null }))

import PrioritizationError from '../error'

describe('the Prioritization error boundary', () => {
  it('says a page broke, not that data failed to load, and retries in place', async () => {
    const reset = vi.fn()
    render(<PrioritizationError error={new TypeError("reading 'icon'")} reset={reset} />)
    expect(screen.getByText(/could not be shown/i)).toBeInTheDocument()
    expect(screen.queryByText(/failed to load/i)).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(reset).toHaveBeenCalled()
  })

  it('offers a reload when the code chunk did not load after a deploy', () => {
    const err = new Error('Loading chunk 42 failed.')
    err.name = 'ChunkLoadError'
    render(<PrioritizationError error={err} reset={vi.fn()} />)
    expect(screen.getByText(/updated while it was open/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument()
  })
})
