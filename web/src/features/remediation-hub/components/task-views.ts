import type { TaskListFilters } from '../api/use-remediation-hub'

/**
 * The task views of /remediation/tasks (`?view=`) and the filters each one
 * sends. Page links and strip tiles count with these same filters, so a number
 * equals the list it opens.
 */
export type TaskView = 'open' | 'mine' | 'verifying' | 'on_hold' | 'closed' | 'all'

export const VIEW_FILTERS: Record<TaskView, Pick<TaskListFilters, 'states' | 'mine'>> = {
  open: { states: ['open', 'in_progress', 'verifying'] },
  mine: { states: ['open', 'in_progress', 'verifying', 'on_hold'], mine: true },
  verifying: { states: ['verifying'] },
  on_hold: { states: ['on_hold'] },
  closed: { states: ['done', 'closed_unverified', 'canceled', 'archived'] },
  all: {},
}
