'use client'

/**
 * The one place where watchers are managed (research/256): the list with why
 * each person watches, a labelled Remove per row for those who may remove
 * others, Stop watching on your own row, and the add search. A centred dialog
 * on desktop and a bottom sheet on phones (the shared dialog frame).
 *
 * Removing is committed at once and offered back by an undo toast
 * (use-watcher-actions.ts); the toast stays clickable over this dialog.
 */

import { useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import { Bell, Plus } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogBody,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import { UserAvatar } from '../user-avatar'
import type { Participants, Watcher, WorkItemKind } from '../../api/use-participants'
import { watcherReason } from './watcher-reason'

export interface WatcherCandidate {
  id: string
  name: string
}

export interface WatcherPickerSource {
  candidates: WatcherCandidate[]
  isLoading: boolean
  onSearch: (query: string) => void
  /** The caller starts loading candidates when the sheet opens. */
  onOpenChange: (open: boolean) => void
}

export interface ManageWatchersDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Where focus goes back on close (the control that opened the sheet). */
  returnFocusRef?: RefObject<HTMLElement | null>
  kind: WorkItemKind
  participants: Participants
  busy: boolean
  canAdd: boolean
  canRemoveOthers: boolean
  picker?: WatcherPickerSource
  currentUserId?: string
  onSetWatching: (watching: boolean) => Promise<boolean>
  onRemove: (w: Watcher) => Promise<boolean>
  onAdd: (userIds: string[]) => Promise<boolean>
}

/** Rows are 44px tall on phones (touch target), 32px from `md`. */
const ROW_ACTION = 'h-11 shrink-0 px-3 md:h-8'

export function ManageWatchersDialog({
  open,
  onOpenChange,
  returnFocusRef,
  kind,
  participants,
  busy,
  canAdd,
  canRemoveOthers,
  picker,
  currentUserId,
  onSetWatching,
  onRemove,
  onAdd,
}: ManageWatchersDialogProps) {
  const { t } = useTranslation()
  const listRef = useRef<HTMLUListElement>(null)
  const [query, setQuery] = useState('')
  const showAdd = canAdd && !!picker

  const watching = participants.me.state === 'subscribed'
  // You first, then everyone else in the order they started watching.
  const watchers = useMemo(() => {
    const mine = participants.watchers.filter((w) => w.user_id === currentUserId)
    const rest = participants.watchers.filter((w) => w.user_id !== currentUserId)
    return [...mine, ...rest]
  }, [participants.watchers, currentUserId])
  const watcherIds = useMemo(() => new Set(watchers.map((w) => w.user_id)), [watchers])
  const candidates = (picker?.candidates ?? []).filter((c) => !watcherIds.has(c.id))

  // Load candidates while the sheet is open; reset the search when it closes.
  useEffect(() => {
    if (showAdd) picker?.onOpenChange(open)
    if (!open) setQuery('')
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only on open/close
  }, [open, showAdd])

  const remove = async (w: Watcher) => {
    if (await onRemove(w)) listRef.current?.focus()
  }

  const description =
    kind === 'finding'
      ? t('findings.people.sheetDescFinding', 'People here get updates on this finding.')
      : t('findings.people.sheetDescTask', 'People here get updates on this task.')

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="sm"
        onCloseAutoFocus={(e) => {
          const el = returnFocusRef?.current
          if (el && el.isConnected) {
            e.preventDefault()
            el.focus({ preventScroll: true })
          }
        }}
      >
        <DialogHeader>
          <DialogTitle>
            {t('findings.people.sheetTitle', 'Watchers ({count})', {
              count: participants.watcher_count,
            })}
          </DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-5">
          {!watching && (
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm text-muted-foreground">
                {t('findings.people.youAreNotWatching', 'You are not watching.')}
              </p>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className={cn(ROW_ACTION, 'gap-1.5')}
                disabled={busy}
                onClick={() => void onSetWatching(true)}
              >
                <Bell className="size-4" aria-hidden />
                {t('findings.people.watch', 'Watch')}
              </Button>
            </div>
          )}

          {participants.names_visible ? (
            watchers.length > 0 ? (
              <ul
                ref={listRef}
                tabIndex={-1}
                className="-mx-1 divide-y rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring"
                aria-label={t('findings.people.watchers', 'Watchers')}
              >
                {watchers.map((w) => {
                  const mine = w.user_id === currentUserId
                  return (
                    <li key={w.user_id} className="flex items-center gap-3 px-1 py-2">
                      <UserAvatar name={w.name} size="md" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm">
                          {w.name}
                          {mine && (
                            <span className="ms-1 text-muted-foreground">
                              {t('findings.people.you', '(you)')}
                            </span>
                          )}
                        </p>
                        <p className="truncate text-xs text-muted-foreground">
                          {watcherReason(t, w, currentUserId)}
                        </p>
                      </div>
                      {mine ? (
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className={ROW_ACTION}
                          disabled={busy}
                          onClick={() => void onSetWatching(false)}
                        >
                          {t('findings.people.stopWatching', 'Stop watching')}
                        </Button>
                      ) : (
                        canRemoveOthers && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className={cn(ROW_ACTION, 'text-muted-foreground')}
                            disabled={busy}
                            aria-label={t('findings.people.removeName', 'Remove {name}', {
                              name: w.name,
                            })}
                            onClick={() => void remove(w)}
                          >
                            {t('findings.people.remove', 'Remove')}
                          </Button>
                        )
                      )}
                    </li>
                  )
                })}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">
                {t('findings.people.noWatchers', 'Nobody is watching yet.')}
              </p>
            )
          ) : (
            <p className="text-sm text-muted-foreground">
              {t(
                'findings.people.namesHidden',
                'Names are shown to people who can see the member list.'
              )}
            </p>
          )}

          {showAdd && (
            <section className="space-y-2" aria-labelledby="watchers-add-heading">
              <h3 id="watchers-add-heading" className="text-sm font-medium">
                {t('findings.people.addPeople', 'Add people')}
              </h3>
              <Input
                type="search"
                value={query}
                autoComplete="off"
                placeholder={t('findings.people.search', 'Search people')}
                aria-label={t('findings.people.search', 'Search people')}
                onChange={(e) => {
                  setQuery(e.target.value)
                  picker?.onSearch(e.target.value)
                }}
              />
              {picker?.isLoading ? (
                <p className="text-xs text-muted-foreground" aria-live="polite">
                  {t('findings.people.loading', 'Loading people')}
                </p>
              ) : candidates.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  {t('findings.people.noCandidates', 'Nobody to add.')}
                </p>
              ) : (
                <ul
                  className="-mx-1 divide-y"
                  aria-label={t('findings.people.candidates', 'People you can add')}
                >
                  {candidates.map((c) => (
                    <li key={c.id} className="flex items-center gap-3 px-1 py-1.5">
                      <UserAvatar name={c.name} size="md" />
                      <span className="min-w-0 flex-1 truncate text-sm">{c.name}</span>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className={cn(ROW_ACTION, 'gap-1.5')}
                        disabled={busy}
                        aria-label={t('findings.people.addName', 'Add {name}', { name: c.name })}
                        onClick={() => void onAdd([c.id])}
                      >
                        <Plus className="size-4" aria-hidden />
                        {t('findings.people.add', 'Add')}
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
              <p className="text-xs text-muted-foreground">
                {kind === 'finding'
                  ? t('findings.people.onlyReaders', 'Only people who can see this are listed.')
                  : t(
                      'findings.people.taskCandidatesHint',
                      'Anyone in the workspace can be listed; people who cannot open this task cannot be added.'
                    )}
              </p>
            </section>
          )}
        </DialogBody>
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="outline" className="h-11 md:h-9">
              {t('findings.people.done', 'Done')}
            </Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
