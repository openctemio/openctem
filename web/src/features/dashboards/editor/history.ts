/**
 * Undo and redo for one editing session of a dashboard layout. Pure: the
 * editor keeps the state in a reducer; Save persists `present`, Cancel
 * throws the whole history away.
 */

export interface History<T> {
  past: T[]
  present: T
  future: T[]
}

/** How many steps the editor keeps. */
export const HISTORY_LIMIT = 100

export function initHistory<T>(present: T): History<T> {
  return { past: [], present, future: [] }
}

/** Records a new state; a change that equals the present is not a step. */
export function push<T>(h: History<T>, next: T): History<T> {
  if (Object.is(next, h.present)) return h
  const past = [...h.past, h.present]
  return { past: past.slice(-HISTORY_LIMIT), present: next, future: [] }
}

export function undo<T>(h: History<T>): History<T> {
  if (h.past.length === 0) return h
  const prev = h.past[h.past.length - 1]
  return { past: h.past.slice(0, -1), present: prev, future: [h.present, ...h.future] }
}

export function redo<T>(h: History<T>): History<T> {
  if (h.future.length === 0) return h
  const [next, ...rest] = h.future
  return { past: [...h.past, h.present], present: next, future: rest }
}
