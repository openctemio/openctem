'use client'

/**
 * A finding's activity trigger + panel. The finding page, the findings-list
 * drawer and the pentest finding sheet all render this, so the three cannot
 * drift apart.
 */

import { forwardRef } from 'react'
import { useCanMutate } from '@/lib/permissions'
import {
  EntityActivity,
  type EntityActivityHandle,
} from '@/features/activity/components/entity-activity'
import type { UseActivityPanelOptions } from '@/features/activity/hooks/use-activity-panel'
import {
  useFindingActivityFeed,
  type FindingActivityFeed,
} from '../hooks/use-finding-activity-feed'
import type { Activity } from '../types'

export interface FindingActivityProps {
  findingId: string
  /** The finding's title, under the panel title. */
  subject?: string
  /** Synthetic entries from the finding record ("Recorded by …"). */
  fromFinding?: Activity[]
  /** Fetch nothing while false (a closed drawer). */
  enabled?: boolean
  /** `?activity=open` on a page; `false` in a drawer. */
  urlParam?: UseActivityPanelOptions['urlParam']
  legacyTab?: UseActivityPanelOptions['legacyTab']
  /** `C` opens the composer. One per page. */
  shortcut?: boolean
  /**
   * Extra reason the viewer may not comment (a locked pentest campaign); the
   * `findings:write` permission is always required.
   */
  readOnly?: boolean
  onTriageActivity?: () => void
  className?: string
}

export const FindingActivity = forwardRef<EntityActivityHandle, FindingActivityProps>(
  function FindingActivity({ enabled = true, fromFinding, onTriageActivity, ...props }, ref) {
    const feed = useFindingActivityFeed(props.findingId, {
      enabled,
      fromFinding,
      onTriageActivity,
    })
    return <FindingActivityView ref={ref} feed={feed} {...props} />
  }
)

export interface FindingActivityViewProps extends Omit<
  FindingActivityProps,
  'enabled' | 'fromFinding' | 'onTriageActivity'
> {
  /** The page already runs `useFindingActivityFeed` (it also needs the raw activities). */
  feed: FindingActivityFeed
}

export const FindingActivityView = forwardRef<EntityActivityHandle, FindingActivityViewProps>(
  function FindingActivityView(
    { feed, findingId, subject, urlParam, legacyTab, shortcut, readOnly, className },
    ref
  ) {
    // POST /findings/{id}/comments needs findings:comment; without it the
    // composer is not offered (instead of a 403 on Send).
    const canComment = useCanMutate('POST /api/v1/findings/{id}/comments') && !readOnly

    return (
      <EntityActivity
        ref={ref}
        entityKey={`finding:${findingId}`}
        subject={subject}
        items={feed.items}
        total={feed.total}
        loading={feed.loading}
        error={feed.error}
        onRetry={() => void feed.retry()}
        hasOlder={feed.hasOlder}
        loadingOlder={feed.loadingOlder}
        onLoadOlder={feed.loadOlder}
        live={feed.live}
        composer={canComment ? { onSend: feed.sendComment, allowInternal: true } : undefined}
        onEditComment={canComment ? feed.editComment : undefined}
        onDeleteComment={canComment ? feed.deleteComment : undefined}
        onToggleReaction={canComment ? feed.toggleReaction : undefined}
        urlParam={urlParam}
        legacyTab={legacyTab}
        shortcut={shortcut}
        triggerClassName={className}
        emptyDescription={canComment ? 'Start the discussion below.' : undefined}
      />
    )
  }
)
