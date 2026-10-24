'use client'

/**
 * Watcher writes with an undo toast (research/213: a reversible change to one
 * item gets no confirmation, it gets Undo). Every write is committed at once
 * and Undo sends the inverse command, so what the server holds is always what
 * the person saw: closing the page during the toast loses nothing.
 *
 * - Removing someone: DELETE, Undo adds them back (the restored row reads
 *   "Added by you"; nobody is notified either way).
 * - Your own bell: PUT subscribed / unsubscribed, Undo flips it back.
 */

import { useCallback } from 'react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { useParticipants, type Watcher, type WorkItemKind } from '../../api/use-participants'

/** Long enough to notice a mis-tap and reach Undo (research/213: at least 8 s). */
export const UNDO_TOAST_MS = 10_000

export function useWatcherActions(kind: WorkItemKind, itemId: string) {
  const { t } = useTranslation()
  const p = useParticipants(kind, itemId, {
    errorMessage: t('findings.people.updateFailed', 'Could not update watchers'),
  })
  const { setWatching: put, addWatchers, removeWatcher } = p
  const undoLabel = t('findings.people.undo', 'Undo')

  const setWatching = useCallback(
    async (next: boolean) => {
      if (!(await put(next))) return false
      const message = next
        ? kind === 'finding'
          ? t('findings.people.startedFinding', 'You are watching this finding')
          : t('findings.people.startedTask', 'You are watching this task')
        : kind === 'finding'
          ? t('findings.people.stoppedFinding', 'You stopped watching this finding')
          : t('findings.people.stoppedTask', 'You stopped watching this task')
      toast.success(message, {
        duration: UNDO_TOAST_MS,
        action: { label: undoLabel, onClick: () => void put(!next) },
      })
      return true
    },
    [put, kind, t, undoLabel]
  )

  const remove = useCallback(
    async (w: Watcher) => {
      if (!(await removeWatcher(w.user_id))) return false
      toast.success(
        t('findings.people.removed', '{name} removed from watchers', { name: w.name }),
        {
          duration: UNDO_TOAST_MS,
          action: {
            label: undoLabel,
            onClick: async () => {
              if (await addWatchers([w.user_id])) {
                toast.success(
                  t('findings.people.restored', '{name} is watching again', { name: w.name })
                )
              }
            },
          },
        }
      )
      return true
    },
    [removeWatcher, addWatchers, t, undoLabel]
  )

  const add = useCallback((userIds: string[]) => addWatchers(userIds), [addWatchers])

  return {
    participants: p.participants,
    isLoading: p.isLoading,
    busy: p.busy,
    setWatching,
    remove,
    add,
  }
}
