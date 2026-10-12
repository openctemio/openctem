'use client'

/**
 * The one way to show an entity's activity: an ActivityTrigger in the page
 * and the ActivityPanel it opens. Every page and drawer with an activity feed
 * or comment thread renders this (owner rule: one shared component).
 *
 *   <EntityActivity
 *     entityKey={`finding:${id}`}
 *     subject={finding.title}
 *     items={items}
 *     composer={{ onSend, allowInternal: true }}
 *     shortcut
 *   />
 */

import { forwardRef, useCallback, useImperativeHandle, useMemo } from 'react'
import { useDisplayUser } from '@/hooks/use-display-user'
import { countUnread } from '../lib/activity-feed'
import {
  useActivityPanel,
  useActivitySeen,
  type UseActivityPanelOptions,
} from '../hooks/use-activity-panel'
import { ActivityPanel, type ActivityPanelProps } from './activity-panel'
import { ActivityTrigger } from './activity-trigger'

export interface EntityActivityProps extends Omit<
  ActivityPanelProps,
  'open' | 'onOpenChange' | 'lastSeen' | 'onSeen' | 'focusComposer' | 'returnFocusRef' | 'viewer'
> {
  /** `?activity=open` by default; `false` in a drawer (state stays local). */
  urlParam?: UseActivityPanelOptions['urlParam']
  legacyTab?: UseActivityPanelOptions['legacyTab']
  /** `C` opens the panel with the composer focused. One per page. */
  shortcut?: boolean
  triggerClassName?: string
  triggerVariant?: 'card' | 'plain'
  /** Replaces the trigger's "N comments" / "N events". */
  triggerHeadline?: string
}

/** Lets a host open the panel (a drawer's own keyboard shortcut). */
export interface EntityActivityHandle {
  open: (opts?: { compose?: boolean }) => void
}

export const EntityActivity = forwardRef<EntityActivityHandle, EntityActivityProps>(
  function EntityActivity(
    { urlParam, legacyTab, shortcut, triggerClassName, triggerVariant, triggerHeadline, ...panel },
    ref
  ) {
    const user = useDisplayUser()
    const viewer = useMemo(
      () => (user ? { id: user.id, name: user.name || user.email } : undefined),
      [user]
    )
    const { open, setOpen, openPanel, composeOnOpen, triggerRef } = useActivityPanel({
      urlParam,
      legacyTab,
    })
    useImperativeHandle(ref, () => ({ open: openPanel }), [openPanel])
    const { lastSeen, markSeen } = useActivitySeen(viewer?.id, panel.entityKey)
    const unread = open ? 0 : countUnread(panel.items, lastSeen, viewer?.id)
    const onSeen = useCallback(() => markSeen(), [markSeen])

    return (
      <>
        <ActivityTrigger
          ref={triggerRef}
          items={panel.items}
          total={panel.total}
          unread={unread}
          loading={panel.loading}
          onOpen={openPanel}
          shortcut={shortcut && !!panel.composer}
          panelOpen={open}
          emptyText={panel.composer ? 'Nothing yet. Open to comment.' : 'Nothing yet.'}
          className={triggerClassName}
          variant={triggerVariant}
          headline={triggerHeadline}
        />
        <ActivityPanel
          {...panel}
          open={open}
          onOpenChange={setOpen}
          viewer={viewer}
          lastSeen={lastSeen}
          onSeen={onSeen}
          focusComposer={composeOnOpen}
          returnFocusRef={triggerRef}
        />
      </>
    )
  }
)
