import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, renderHook, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { resetScanTriggerStateForTests, useScanTrigger } from '../use-scan-trigger'

// Live use (2026-10-04): two "Trigger" clicks 12 s apart started a second
// manual run while the first was still running on the same host.
const getMock = vi.fn()
const postMock = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...a: unknown[]) => getMock(...a),
  post: (...a: unknown[]) => postMock(...a),
}))
vi.mock('@/lib/api/scan-hooks', () => ({ invalidateScanConfigsCache: vi.fn() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const scan = { id: 's1', name: 'Nightly recon' }
const notFound = Object.assign(new Error('not found'), { statusCode: 404 })

function Harness({ onViewRun }: { onViewRun?: (id: string) => void }) {
  const { trigger, isTriggering, dialog } = useScanTrigger({ onViewRun })
  return (
    <>
      <button onClick={() => void trigger(scan)} disabled={isTriggering(scan.id)}>
        Trigger
      </button>
      <span data-testid="busy">{String(isTriggering(scan.id))}</span>
      {dialog}
    </>
  )
}

describe('useScanTrigger', () => {
  beforeEach(() => {
    getMock.mockReset()
    postMock.mockReset()
    resetScanTriggerStateForTests()
  })

  it('triggers at once when the scan has no run in progress', async () => {
    getMock.mockRejectedValue(notFound)
    postMock.mockResolvedValue({})
    render(<Harness />)
    await userEvent.click(screen.getByRole('button', { name: 'Trigger' }))
    expect(postMock).toHaveBeenCalledTimes(1)
    expect(postMock.mock.calls[0][0]).toBe('/api/v1/scans/s1/trigger')
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
  })

  it('ignores a second trigger while the first is in flight', async () => {
    getMock.mockResolvedValue({ id: 'r0', status: 'completed' })
    let release: (v: unknown) => void = () => {}
    postMock.mockReturnValue(new Promise((r) => (release = r)))
    const { result } = renderHook(() => useScanTrigger())
    await act(async () => {
      const first = result.current.trigger(scan)
      const second = result.current.trigger(scan)
      await second
      release({})
      await first
    })
    expect(postMock).toHaveBeenCalledTimes(1)
  })

  it('asks before starting a second run while one is in progress', async () => {
    getMock.mockResolvedValue({
      id: 'r1',
      status: 'running',
      created_at: '2026-10-04T10:00:00Z',
      task_summary: { total: 5, completed: 3 },
    })
    postMock.mockResolvedValue({})
    render(<Harness />)
    await userEvent.click(screen.getByRole('button', { name: 'Trigger' }))

    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('A run is already in progress')
    expect(dialog).toHaveTextContent('3/5 tasks')
    expect(postMock).not.toHaveBeenCalled()
    // Still guarded while the question is open.
    expect(screen.getByTestId('busy')).toHaveTextContent('true')

    await userEvent.click(screen.getByRole('button', { name: 'Start another run' }))
    expect(postMock).toHaveBeenCalledTimes(1)
  })

  it('starts nothing when the user cancels, and frees the button', async () => {
    getMock.mockResolvedValue({ id: 'r1', status: 'pending', created_at: '2026-10-04T10:00:00Z' })
    render(<Harness />)
    await userEvent.click(screen.getByRole('button', { name: 'Trigger' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(postMock).not.toHaveBeenCalled()
    expect(screen.getByTestId('busy')).toHaveTextContent('false')
  })

  it('offers to open the running run', async () => {
    getMock.mockResolvedValue({ id: 'r9', status: 'running', created_at: '2026-10-04T10:00:00Z' })
    const onViewRun = vi.fn()
    render(<Harness onViewRun={onViewRun} />)
    await userEvent.click(screen.getByRole('button', { name: 'Trigger' }))
    await userEvent.click(await screen.findByRole('button', { name: 'View the running run' }))
    expect(onViewRun).toHaveBeenCalledWith('r9')
    expect(postMock).not.toHaveBeenCalled()
  })

  it('still triggers when the latest-run check fails', async () => {
    getMock.mockRejectedValue(Object.assign(new Error('boom'), { statusCode: 500 }))
    postMock.mockResolvedValue({})
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    render(<Harness />)
    await userEvent.click(screen.getByRole('button', { name: 'Trigger' }))
    expect(postMock).toHaveBeenCalledTimes(1)
  })
})
