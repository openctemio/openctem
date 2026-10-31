'use client'

import * as React from 'react'

/**
 * Shows a page's skeleton until the blocks that load their own data have
 * answered, then shows the page in one step, so a band or a side panel that
 * arrives a moment after the main record does not push what the reader is
 * already looking at (cumulative layout shift).
 *
 * The children mount at once, hidden, so their requests start in parallel
 * with nothing waiting on the group. A block opts in with
 * `useSettleSignal(isLoading)`; outside a group the hook does nothing, so a
 * shared block (watchers, a side panel) can call it everywhere. The group
 * waits at most `maxWaitMs`: a slow block then loads in place as before.
 * After the first reveal the group never hides its children again.
 */
type Report = (id: symbol, pending: boolean) => void

const SettleContext = React.createContext<Report | null>(null)

export interface SettleGroupProps {
  /** What to show while waiting: a skeleton shaped like the page. */
  fallback: React.ReactNode
  children: React.ReactNode
  /** Longest wait for slow blocks, in ms. */
  maxWaitMs?: number
}

export function SettleGroup({ fallback, children, maxWaitMs = 1500 }: SettleGroupProps) {
  const pending = React.useRef(new Set<symbol>())
  const [released, setReleased] = React.useState(false)
  const [tick, setTick] = React.useState(0)

  const report = React.useCallback<Report>((id, isPending) => {
    const set = pending.current
    const had = set.has(id)
    if (isPending && !had) set.add(id)
    else if (!isPending && had) set.delete(id)
    else return
    setTick((n) => n + 1)
  }, [])

  // Children report in their layout effects, before this effect runs, so the
  // first check already knows every block that is still loading.
  React.useEffect(() => {
    if (!released && pending.current.size === 0) setReleased(true)
  }, [released, tick])

  React.useEffect(() => {
    if (released) return
    const timer = window.setTimeout(() => setReleased(true), maxWaitMs)
    return () => window.clearTimeout(timer)
  }, [released, maxWaitMs])

  return (
    <SettleContext.Provider value={released ? null : report}>
      {!released && fallback}
      {/* `contents` once shown: the blocks stay direct children of the
          page's layout (a PageStack's gaps apply to them). */}
      <div
        hidden={!released}
        className={released ? 'contents' : undefined}
        data-slot="settle-group"
      >
        {children}
      </div>
    </SettleContext.Provider>
  )
}

/** Tells the enclosing `SettleGroup` (if any) whether this block is still loading. */
export function useSettleSignal(isPending: boolean) {
  const report = React.useContext(SettleContext)
  const id = React.useRef<symbol | null>(null)
  if (id.current === null) id.current = Symbol('settle')
  React.useLayoutEffect(() => {
    report?.(id.current as symbol, isPending)
  }, [report, isPending])
  React.useLayoutEffect(() => {
    const own = id.current as symbol
    return () => report?.(own, false)
  }, [report])
}

/** A `useSettleSignal` for data the page itself loads outside its blocks. */
export function SettleSignal({ pending }: { pending: boolean }) {
  useSettleSignal(pending)
  return null
}
