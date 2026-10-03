'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useUrlFilter, useUrlParam } from '@/hooks/use-url-param'
import { readLastSeen, writeLastSeen } from '../lib/activity-storage'

export interface UseActivityPanelOptions {
  /**
   * The URL parameter that holds the open state (`?activity=open`), so a link
   * can open the panel. `false` keeps it in memory: a drawer over a list page
   * should not leave a parameter behind when it closes.
   */
  urlParam?: string | false
  /**
   * An old link to the Activity tab (`?tab=activity`) opens the panel and the
   * parameter is dropped. Only with a URL parameter.
   */
  legacyTab?: { param: string; value: string } | false
}

/**
 * Open state, trigger ref and "compose on open" of one entity's ActivityPanel.
 * The page renders `<ActivityTrigger ref={triggerRef} …>` and
 * `<ActivityPanel open={open} … returnFocusRef={triggerRef}>`.
 */
export function useActivityPanel({
  urlParam = 'activity',
  legacyTab = { param: 'tab', value: 'activity' },
}: UseActivityPanelOptions = {}) {
  const param = urlParam || '__activity_local__'
  const [urlValue, setUrlValue] = useUrlFilter(param, '')
  const [localOpen, setLocalOpen] = useState(false)
  const [composeOnOpen, setComposeOnOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)

  const open = urlParam ? urlValue === 'open' : localOpen

  const setOpen = useCallback(
    (next: boolean) => {
      if (!next) setComposeOnOpen(false)
      if (urlParam) setUrlValue(next ? 'open' : '')
      else setLocalOpen(next)
    },
    [urlParam, setUrlValue]
  )

  const openPanel = useCallback(
    (opts?: { compose?: boolean }) => {
      setComposeOnOpen(!!opts?.compose)
      setOpen(true)
    },
    [setOpen]
  )

  // Backward compatibility: `?tab=activity` (the old Activity tab) opens the panel.
  const legacyParam = legacyTab && urlParam ? legacyTab.param : '__activity_no_legacy__'
  const legacyWanted = legacyTab && urlParam ? legacyTab.value : null
  const legacyValue = useUrlParam(legacyParam)
  const [, setLegacy] = useUrlFilter(legacyParam, '')
  useEffect(() => {
    if (legacyWanted && legacyValue === legacyWanted) {
      setLegacy('')
      setUrlValue('open')
    }
  }, [legacyWanted, legacyValue, setLegacy, setUrlValue])

  return { open, setOpen, openPanel, composeOnOpen, triggerRef }
}

/**
 * When the viewer last looked at an entity's activity (epoch ms, or null),
 * from browser storage; `markSeen` records "now".
 */
export function useActivitySeen(viewerId: string | undefined, entityKey: string) {
  const [lastSeen, setLastSeen] = useState<number | null>(null)

  useEffect(() => {
    setLastSeen(readLastSeen(viewerId, entityKey))
  }, [viewerId, entityKey])

  const markSeen = useCallback(
    (at: number = Date.now()) => {
      writeLastSeen(viewerId, entityKey, at)
      setLastSeen(at)
    },
    [viewerId, entityKey]
  )

  return { lastSeen, markSeen }
}
