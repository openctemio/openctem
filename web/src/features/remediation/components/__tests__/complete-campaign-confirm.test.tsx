/**
 * Completing a remediation campaign with open findings asks first and says
 * how many; with nothing open it completes straight away.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const mockGet = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...args: unknown[]) => mockGet(...args),
}))

import { useConfirmCampaignCompletion } from '../complete-campaign-confirm'
import type { CampaignCounts } from '@/features/remediation/lib/campaign-completion'

function Harness({
  ids,
  proceed,
  fallback,
}: {
  ids: string[]
  proceed: () => void
  fallback?: Record<string, CampaignCounts>
}) {
  const { confirmCompletion, completionDialog } = useConfirmCampaignCompletion()
  return (
    <>
      <button type="button" onClick={() => void confirmCompletion(ids, proceed, fallback)}>
        Complete
      </button>
      {completionDialog}
    </>
  )
}

async function clickComplete() {
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Complete' }))
  return user
}

describe('useConfirmCampaignCompletion', () => {
  beforeEach(() => {
    mockGet.mockReset()
  })

  it('asks before completing a campaign with 0 of 4 findings closed, and completes on confirm', async () => {
    mockGet.mockResolvedValue({ finding_count: 4, resolved_count: 0 })
    const proceed = vi.fn()
    render(<Harness ids={['c1']} proceed={proceed} />)

    const user = await clickComplete()

    expect(await screen.findByText('Complete with open findings?')).toBeInTheDocument()
    expect(screen.getByText('4 of 4 findings are still open.')).toBeInTheDocument()
    expect(proceed).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Complete anyway' }))
    expect(proceed).toHaveBeenCalledTimes(1)
  })

  it('does not complete when the user cancels', async () => {
    mockGet.mockResolvedValue({ finding_count: 4, resolved_count: 1 })
    const proceed = vi.fn()
    render(<Harness ids={['c1']} proceed={proceed} />)

    const user = await clickComplete()
    expect(await screen.findByText('3 of 4 findings are still open.')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(proceed).not.toHaveBeenCalled()
    expect(screen.queryByText('Complete with open findings?')).not.toBeInTheDocument()
  })

  it('completes without asking when every finding is closed', async () => {
    mockGet.mockResolvedValue({ finding_count: 4, resolved_count: 4 })
    const proceed = vi.fn()
    render(<Harness ids={['c1']} proceed={proceed} />)

    await clickComplete()

    await vi.waitFor(() => expect(proceed).toHaveBeenCalledTimes(1))
    expect(screen.queryByText('Complete with open findings?')).not.toBeInTheDocument()
  })

  it('still asks when the live counts cannot be read, using the counts on the page', async () => {
    mockGet.mockRejectedValue(new Error('offline'))
    const proceed = vi.fn()
    render(
      <Harness
        ids={['c1']}
        proceed={proceed}
        fallback={{ c1: { finding_count: 4, resolved_count: 0 } }}
      />
    )

    await clickComplete()

    expect(await screen.findByText('4 of 4 findings are still open.')).toBeInTheDocument()
    expect(proceed).not.toHaveBeenCalled()
  })

  it('words a bulk completion for several tasks', async () => {
    mockGet
      .mockResolvedValueOnce({ finding_count: 4, resolved_count: 0 })
      .mockResolvedValueOnce({ finding_count: 2, resolved_count: 2 })
    render(<Harness ids={['c1', 'c2']} proceed={vi.fn()} />)

    await clickComplete()

    expect(await screen.findByText('Complete tasks with open findings?')).toBeInTheDocument()
    expect(screen.getByText('4 of 6 findings in 1 task are still open.')).toBeInTheDocument()
  })
})
