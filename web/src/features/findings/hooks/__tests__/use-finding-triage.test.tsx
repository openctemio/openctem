/**
 * useFindingTriage — the "follow the server" effects must not loop.
 *
 * The parent (findings detail page / drawer) rebuilds the `finding` object — and
 * a fresh `assignee` object — on every render. Keying the sync effects on the
 * assignee OBJECT, or calling setState unconditionally with a new reference,
 * re-fires the effect every render and the page throws "Maximum update depth
 * exceeded". These tests pin the primitive-keyed, idempotent behaviour.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, render } from '@testing-library/react'

import { useFindingTriage, type FindingTriageTarget } from '../use-finding-triage'
import type { FindingUser } from '../../types'

// The API mutation hooks: never actually called in these tests, but the hook
// wires them up on mount.
vi.mock('../../api/use-findings-api', () => ({
  invalidateFindingsCache: vi.fn(),
  useUpdateFindingStatusApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useUpdateFindingSeverityApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useAssignFindingApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useUnassignFindingApi: () => ({ trigger: vi.fn(), isMutating: false }),
}))

vi.mock('../../components/approval-dialog', () => ({
  ApprovalDialog: () => null,
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const user = (id: string, name = id): FindingUser => ({
  id,
  name,
  email: `${id}@example.test`,
  role: 'member' as FindingUser['role'],
})

const target = (over: Partial<FindingTriageTarget> = {}): FindingTriageTarget => ({
  id: 'f1',
  status: 'new',
  severity: 'high',
  ...over,
})

beforeEach(() => vi.clearAllMocks())

describe('useFindingTriage — no render loop', () => {
  it('keeps the assignee stable when the parent passes a NEW object with the same id', () => {
    const { result, rerender } = renderHook(({ f }) => useFindingTriage(f), {
      initialProps: { f: target({ assignee: user('u1', 'Alice') }) },
    })

    const first = result.current.assignee
    expect(first?.id).toBe('u1')

    // The parent re-renders with a brand-new assignee object (same person). The
    // effect must NOT adopt the new reference — that would be a new state value
    // every render and loop.
    rerender({ f: target({ assignee: user('u1', 'Alice') }) })
    expect(result.current.assignee).toBe(first)

    rerender({ f: target({ assignee: user('u1', 'Alice') }) })
    expect(result.current.assignee).toBe(first)
  })

  it('follows the server when the assignee actually changes', () => {
    const { result, rerender } = renderHook(({ f }) => useFindingTriage(f), {
      initialProps: { f: target({ assignee: user('u1') }) },
    })
    expect(result.current.assignee?.id).toBe('u1')

    rerender({ f: target({ assignee: user('u2') }) })
    expect(result.current.assignee?.id).toBe('u2')

    rerender({ f: target({ assignee: undefined }) })
    expect(result.current.assignee).toBeUndefined()
  })

  it('follows the server on status and severity, idempotently', () => {
    const { result, rerender } = renderHook(({ f }) => useFindingTriage(f), {
      initialProps: { f: target({ status: 'new', severity: 'high' }) },
    })
    expect(result.current.status).toBe('new')
    expect(result.current.severity).toBe('high')

    rerender({ f: target({ status: 'confirmed', severity: 'critical' }) })
    expect(result.current.status).toBe('confirmed')
    expect(result.current.severity).toBe('critical')
  })

  // The real-world reproduction: a parent that rebuilds the finding (and its
  // assignee object) on every single render. Before the fix this re-fired the
  // assignee effect each render, which setState'd a new reference, which
  // re-rendered — an unbounded loop that React aborts with "Maximum update depth
  // exceeded". With the fix the component settles to a small, bounded number of
  // renders.
  it('settles (bounded render count) when the parent recreates the finding every render', () => {
    let renders = 0
    function Harness() {
      renders += 1
      // Fresh objects every render — exactly what toFindingDetail(apiFinding) does.
      const finding = target({ assignee: user('u1', 'Alice') })
      useFindingTriage(finding)
      return null
    }

    expect(() => render(<Harness />)).not.toThrow()
    // A loop would blow past React's ~50 update-depth limit. A handful (mount +
    // StrictMode double-invoke + one settling pass) is expected.
    expect(renders).toBeLessThan(10)
  })
})
