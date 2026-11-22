/**
 * A task's timeline shows its latest events and folds the rest behind one
 * button, so a long-running task keeps a short page.
 */

import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const events = Array.from({ length: 14 }, (_, i) => ({
  id: `e${i}`,
  kind: 'created',
  actor_type: 'system',
  actor_id: '',
  created_at: '2026-11-01T00:00:00Z',
  data: {},
}))

vi.mock('@/hooks/use-near-viewport', () => ({ useNearViewport: () => true }))
vi.mock('../api/use-remediation-hub', () => ({
  useTaskTimeline: () => ({ data: { data: events } }),
}))
vi.mock('../api/use-owner-names', () => ({
  useOwnerLabels: () => ({ user: () => undefined, group: () => undefined }),
}))
vi.mock('../components/task-query-panel', () => ({ TaskQueryPanel: () => null }))

import { TaskHistory, TIMELINE_SHOWN } from '../components/task-history'

describe('TaskHistory', () => {
  it('shows the first events and the rest on request', () => {
    render(
      <TaskHistory task={{ id: 't', version: 1 } as never} writable={false} onChanged={() => {}} />
    )
    expect(screen.getAllByRole('listitem')).toHaveLength(TIMELINE_SHOWN)
    fireEvent.click(screen.getByRole('button', { name: /Show all events \(14\)/ }))
    expect(screen.getAllByRole('listitem')).toHaveLength(14)
  })
})
