'use client'

/**
 * Everything a finding's ActivityPanel needs, in one hook shared by the
 * finding page, the findings-list drawer and the pentest finding sheet:
 *
 * - the paged activities (GET /findings/{id}/activities) and the live channel,
 * - the comments (GET /findings/{id}/comments: text, Internal, edited, reactions),
 * - send / edit / delete a comment and toggle a reaction.
 */

import { useCallback, useMemo } from 'react'
import useSWR from 'swr'
import { del, get, post, put } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { ActivityCommentItem, ActivityItem, ActivityReaction } from '@/features/activity/types'
import type { ActivityLiveStatus } from '@/features/activity/components/activity-panel'
import type { ApiCommentReaction, ApiFindingComment } from '../api/finding-api.types'
import { useFindingActivitiesInfinite } from '../api/use-finding-activities-api'
import { useActivityStream } from './use-activity-stream'
import { mergeFindingActivities } from '../lib/finding-activities'
import { toActivityReactions, toFindingActivityItems } from '../lib/finding-activity-items'
import type { Activity, ActivityType } from '../types'

interface CommentList {
  data: ApiFindingComment[]
  total?: number
}

export interface UseFindingActivityFeedOptions {
  /** Fetch nothing while false (a closed drawer). */
  enabled?: boolean
  /** Subscribe to the finding's live channel. */
  live?: boolean
  /** Synthetic entries from the finding record ("Recorded by …"). */
  fromFinding?: Activity[]
  /** Called for AI-triage activities, so the page can refresh its triage card. */
  onTriageActivity?: () => void
}

const TRIAGE: ActivityType[] = ['ai_triage', 'ai_triage_failed']

export function commentsKey(findingId: string) {
  return `/api/v1/findings/${findingId}/comments`
}

export function useFindingActivityFeed(
  findingId: string | null,
  { enabled = true, live = true, fromFinding, onTriageActivity }: UseFindingActivityFeedOptions = {}
) {
  const { currentTenant } = useTenant()
  const id = enabled && findingId ? findingId : null

  const {
    activities: fetched,
    total: fetchedTotal,
    isLoading,
    isLoadingMore,
    isReachingEnd,
    loadMore,
    error: activitiesError,
    mutate: mutateActivities,
  } = useFindingActivitiesInfinite(id)

  const {
    data: commentList,
    error: commentsError,
    isLoading: commentsLoading,
    mutate: mutateComments,
  } = useSWR<CommentList>(id && currentTenant ? commentsKey(id) : null, (url: string) =>
    get<CommentList>(url)
  )

  const { realtimeActivities, status, clearActivities } = useActivityStream(id, {
    enabled: !!id && live,
    onActivity: (a) => {
      void mutateActivities()
      if (a.type === 'comment') void mutateComments()
      if (TRIAGE.includes(a.type)) onTriageActivity?.()
    },
    onEvent: (e) => {
      if (e.type === 'reactions_updated') void mutateComments()
    },
  })

  const { activities, count } = mergeFindingActivities({
    fetched,
    fetchedTotal,
    realtime: realtimeActivities,
    fromFinding,
  })

  const items: ActivityItem[] = useMemo(
    () => toFindingActivityItems(activities, commentsError ? undefined : commentList?.data),
    [activities, commentList, commentsError]
  )

  const refresh = useCallback(async () => {
    await Promise.all([mutateActivities(), mutateComments()])
    clearActivities()
  }, [mutateActivities, mutateComments, clearActivities])

  const sendComment = useCallback(
    async (body: string, opts: { internal: boolean }) => {
      if (!findingId) return
      await post(commentsKey(findingId), {
        content: body,
        ...(opts.internal ? { is_internal: true } : {}),
      })
      await refresh()
    },
    [findingId, refresh]
  )

  const editComment = useCallback(
    async (item: ActivityCommentItem, body: string) => {
      if (!findingId || !item.commentId) return
      await put(`${commentsKey(findingId)}/${item.commentId}`, { content: body })
      await refresh()
    },
    [findingId, refresh]
  )

  const deleteComment = useCallback(
    async (item: ActivityCommentItem) => {
      if (!findingId || !item.commentId) return
      await del(`${commentsKey(findingId)}/${item.commentId}`)
      await refresh()
    },
    [findingId, refresh]
  )

  const toggleReaction = useCallback(
    async (
      item: ActivityCommentItem,
      emoji: string,
      add: boolean
    ): Promise<ActivityReaction[] | void> => {
      if (!item.commentId) throw new Error('This comment cannot take reactions yet')
      const base = `/api/v1/comments/${encodeURIComponent(item.commentId)}/reactions`
      const res = add
        ? await post<{ data?: ApiCommentReaction[] }>(base, { emoji })
        : await del<{ data?: ApiCommentReaction[] }>(`${base}/${encodeURIComponent(emoji)}`)
      void mutateComments()
      return res && Array.isArray(res.data) ? toActivityReactions(res.data) : undefined
    },
    [mutateComments]
  )

  const liveStatus: ActivityLiveStatus | undefined = !live
    ? undefined
    : status === 'connected'
      ? 'connected'
      : status === 'connecting'
        ? 'connecting'
        : 'offline'

  return {
    /** The finding's activities as the finding types know them (AI triage card). */
    activities,
    items,
    /** Events + comments the feed knows of (the header count). */
    total: count,
    loading: isLoading || commentsLoading,
    error: activitiesError ?? undefined,
    retry: refresh,
    hasOlder: !isReachingEnd,
    loadingOlder: !!isLoadingMore,
    loadOlder: loadMore,
    live: liveStatus,
    sendComment,
    editComment,
    deleteComment,
    toggleReaction,
    refresh,
  }
}

export type FindingActivityFeed = ReturnType<typeof useFindingActivityFeed>
