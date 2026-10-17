import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApiClientError } from '@/lib/api/error-handler'
import { SubStatusDialog } from '../sub-status-dialog'
import { SubStatusLanes } from '../sub-status-lanes'
import type { LifecycleSubStatus } from '../../../api/use-finding-lifecycles'

if (!('ResizeObserver' in globalThis)) {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

const create = vi.fn()
const update = vi.fn()
const archive = vi.fn()
vi.mock('../../../api/use-finding-lifecycles', async (orig) => ({
  ...(await orig<typeof import('../../../api/use-finding-lifecycles')>()),
  createSubStatus: (...a: unknown[]) => create(...a),
  updateSubStatus: (...a: unknown[]) => update(...a),
  archiveSubStatus: (...a: unknown[]) => archive(...a),
  reactivateSubStatus: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const COLORS = ['gray', 'red', 'blue']

function sub(over: Partial<LifecycleSubStatus> = {}): LifecycleSubStatus {
  return {
    id: '11111111-1111-1111-1111-111111111111',
    key: 'in_review',
    canonical_status: 'in_progress',
    name: 'In review',
    labels: {},
    description: '',
    color: 'blue',
    sort_order: 0,
    archived: false,
    created_at: '2026-10-16T00:00:00Z',
    updated_at: '2026-10-16T00:00:00Z',
    ...over,
  }
}

describe('SubStatusDialog', () => {
  beforeEach(() => {
    create.mockReset()
    update.mockReset()
  })

  it('creates a sub-status in its lane with a key derived from the name', async () => {
    create.mockResolvedValue(sub())
    const onSaved = vi.fn()
    render(
      <SubStatusDialog
        open
        onOpenChange={() => {}}
        status="in_progress"
        colors={COLORS}
        nextSortOrder={2}
        onSaved={onSaved}
      />
    )
    const save = screen.getByRole('button', { name: /save sub-status/i })
    expect(save).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/^name$/i), 'In review')
    expect(screen.getByLabelText(/^key$/i)).toHaveValue('in_review')
    await userEvent.type(screen.getByLabelText(/name in vietnamese/i), 'Đang xem xét')
    await userEvent.click(screen.getByRole('radio', { name: /red/i }))
    await userEvent.click(save)
    expect(create).toHaveBeenCalledWith({
      key: 'in_review',
      canonical_status: 'in_progress',
      closure_reason: undefined,
      name: 'In review',
      labels: { vi: 'Đang xem xét' },
      description: '',
      color: 'red',
      sort_order: 2,
    })
    expect(onSaved).toHaveBeenCalled()
  })

  it('needs a closure reason under a closed status', async () => {
    render(
      <SubStatusDialog
        open
        onOpenChange={() => {}}
        status="accepted"
        colors={COLORS}
        nextSortOrder={0}
        onSaved={() => {}}
      />
    )
    await userEvent.type(screen.getByLabelText(/^name$/i), 'Bounty paid')
    expect(screen.getByLabelText(/closure reason/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /save sub-status/i })).toBeDisabled()
  })

  it('edits only the label: the key and closure reason are fixed', async () => {
    update.mockResolvedValue(sub({ name: 'Peer review' }))
    render(
      <SubStatusDialog
        open
        onOpenChange={() => {}}
        status="new"
        subStatus={sub()}
        colors={COLORS}
        nextSortOrder={0}
        onSaved={() => {}}
      />
    )
    expect(screen.getByLabelText(/^key$/i)).toBeDisabled()
    const name = screen.getByLabelText(/^name$/i)
    await userEvent.clear(name)
    await userEvent.type(name, 'Peer review')
    await userEvent.click(screen.getByRole('button', { name: /save sub-status/i }))
    expect(update).toHaveBeenCalledWith(sub().id, {
      name: 'Peer review',
      labels: {},
      description: '',
      color: 'blue',
    })
  })

  it('says when the limit allows no more sub-statuses', async () => {
    create.mockRejectedValue(new ApiClientError('limit', 'PLAN_LIMIT', 403))
    render(
      <SubStatusDialog
        open
        onOpenChange={() => {}}
        status="new"
        colors={COLORS}
        nextSortOrder={0}
        onSaved={() => {}}
      />
    )
    await userEvent.type(screen.getByLabelText(/^name$/i), 'Waiting')
    await userEvent.click(screen.getByRole('button', { name: /save sub-status/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/limit of sub-statuses/i)
  })
})

describe('SubStatusLanes', () => {
  beforeEach(() => {
    update.mockReset()
    archive.mockReset()
  })

  it('renders a lane per canonical status with its sub-statuses', () => {
    render(
      <SubStatusLanes
        subStatuses={[sub()]}
        colors={COLORS}
        canWrite
        limitReached={false}
        onChanged={() => {}}
      />
    )
    expect(screen.getAllByRole('region')).toHaveLength(8)
    const lane = screen.getByRole('region', { name: /in progress/i })
    expect(within(lane).getByText('In review')).toBeInTheDocument()
  })

  it('is read-only without findings:lifecycles:write', () => {
    render(
      <SubStatusLanes
        subStatuses={[sub()]}
        colors={COLORS}
        canWrite={false}
        limitReached={false}
        onChanged={() => {}}
      />
    )
    expect(screen.queryByRole('button', { name: /actions for in review/i })).not.toBeInTheDocument()
    for (const b of screen.getAllByRole('button', { name: /add a sub-status/i }))
      expect(b).toBeDisabled()
  })

  it('disables adding once the plan limit is reached', () => {
    render(
      <SubStatusLanes
        subStatuses={[sub()]}
        colors={COLORS}
        canWrite
        limitReached
        onChanged={() => {}}
      />
    )
    for (const b of screen.getAllByRole('button', { name: /add a sub-status/i }))
      expect(b).toBeDisabled()
    expect(screen.getByRole('button', { name: /actions for in review/i })).toBeEnabled()
  })

  it('reorders by renumbering the lane', async () => {
    update.mockResolvedValue({})
    const onChanged = vi.fn()
    const a = sub({ id: 'a', name: 'A', key: 'a_one', sort_order: 5 })
    const b = sub({ id: 'b', name: 'B', key: 'b_two', sort_order: 5 })
    render(
      <SubStatusLanes
        subStatuses={[a, b]}
        colors={COLORS}
        canWrite
        limitReached={false}
        onChanged={onChanged}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: /actions for b/i }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /move up/i }))
    expect(update).toHaveBeenCalledWith('b', { sort_order: 0 })
    expect(update).toHaveBeenCalledWith('a', { sort_order: 1 })
    expect(onChanged).toHaveBeenCalled()
  })
})
