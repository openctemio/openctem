import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApiClientError } from '@/lib/api/error-handler'
import { LifecycleDraftEditor } from '../lifecycle-draft-editor'
import type { Lifecycle, LifecycleSubStatus } from '../../../api/use-finding-lifecycles'

if (!('ResizeObserver' in globalThis)) {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

const save = vi.fn()
const test = vi.fn()
const publish = vi.fn()
vi.mock('../../../api/use-finding-lifecycles', async (orig) => ({
  ...(await orig<typeof import('../../../api/use-finding-lifecycles')>()),
  saveLifecycleDraft: (...a: unknown[]) => save(...a),
  testLifecycleVersion: (...a: unknown[]) => test(...a),
  publishLifecycleVersion: (...a: unknown[]) => publish(...a),
  createLifecycleDraft: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const REVIEW: LifecycleSubStatus = {
  id: 'aaaaaaaa-0000-0000-0000-000000000001',
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
}

function lifecycle(over: Partial<Lifecycle> = {}): Lifecycle {
  return {
    id: 'lc-1',
    key: 'default',
    name: 'Default',
    description: '',
    priority: 0,
    default: true,
    context: [],
    archived: false,
    draft: {
      version: 2,
      state: 'draft',
      spec: { sub_statuses: [], transitions: [], person_moves: 'canonical_plus_listed' },
      spec_hash: 'h1',
      note: '',
      created_at: '2026-10-16T00:00:00Z',
    },
    created_at: '2026-10-16T00:00:00Z',
    updated_at: '2026-10-16T00:00:00Z',
    ...over,
  }
}

const VALID = { valid: true, validation: { errors: [], warnings: [] } }

describe('LifecycleDraftEditor', () => {
  beforeEach(() => {
    save.mockReset()
    test.mockReset()
    publish.mockReset()
  })

  it('saves the draft with the hash it read (If-Match) and shows the validation', async () => {
    save.mockResolvedValue({ ...VALID, version: { ...lifecycle().draft!, spec_hash: 'h2' } })
    render(
      <LifecycleDraftEditor
        lifecycle={lifecycle()}
        catalog={[REVIEW]}
        canWrite
        onReload={() => {}}
      />
    )
    const publishBtn = screen.getByRole('button', { name: /^publish$/i })
    expect(publishBtn).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: /use in review/i }))
    await userEvent.click(screen.getByRole('button', { name: /save draft/i }))
    expect(save).toHaveBeenCalledWith(
      'lc-1',
      2,
      'h1',
      expect.objectContaining({ sub_statuses: [REVIEW.id] })
    )
    expect(await screen.findByText(/ready to publish/i)).toBeInTheDocument()
    expect(publishBtn).toBeEnabled()
  })

  it('lists validation errors and keeps publish disabled', async () => {
    test.mockResolvedValue({
      valid: false,
      validation: {
        errors: [
          {
            code: 'unreachable_closed_status',
            path: 'transitions',
            message: 'resolved is unreachable',
          },
        ],
        warnings: [],
      },
    })
    render(
      <LifecycleDraftEditor
        lifecycle={lifecycle()}
        catalog={[REVIEW]}
        canWrite
        onReload={() => {}}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: /^check$/i }))
    expect(await screen.findByText(/resolved is unreachable/i)).toBeInTheDocument()
    expect(screen.getByText(/1 problem/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^publish$/i })).toBeDisabled()
  })

  it('tells the editor when someone else changed the draft (409)', async () => {
    save.mockRejectedValue(new ApiClientError('changed', 'CONFLICT', 409))
    const onReload = vi.fn()
    render(
      <LifecycleDraftEditor
        lifecycle={lifecycle()}
        catalog={[REVIEW]}
        canWrite
        onReload={onReload}
      />
    )
    await userEvent.click(screen.getByRole('checkbox', { name: /use in review/i }))
    await userEvent.click(screen.getByRole('button', { name: /save draft/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/someone else changed this draft/i)
    await userEvent.click(screen.getByRole('button', { name: /reload/i }))
    expect(onReload).toHaveBeenCalled()
  })

  it('publishes a checked draft through the publish dialog', async () => {
    test.mockResolvedValue(VALID)
    publish.mockResolvedValue({ ...lifecycle().draft!, state: 'published' })
    const onReload = vi.fn()
    render(
      <LifecycleDraftEditor
        lifecycle={lifecycle()}
        catalog={[REVIEW]}
        canWrite
        onReload={onReload}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: /^check$/i }))
    await userEvent.click(await screen.findByRole('button', { name: /^publish$/i }))
    await userEvent.type(screen.getByLabelText(/what changed/i), 'First lifecycle')
    const dialogButtons = screen.getAllByRole('button', { name: /^publish$/i })
    await userEvent.click(dialogButtons[dialogButtons.length - 1])
    expect(publish).toHaveBeenCalledWith('lc-1', 2, 'First lifecycle')
    expect(onReload).toHaveBeenCalled()
  })

  it('is read-only without findings:lifecycles:write', () => {
    render(
      <LifecycleDraftEditor
        lifecycle={lifecycle()}
        catalog={[REVIEW]}
        canWrite={false}
        onReload={() => {}}
      />
    )
    expect(screen.getByRole('checkbox', { name: /use in review/i })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /save draft/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^publish$/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /add move/i })).not.toBeInTheDocument()
  })
})
