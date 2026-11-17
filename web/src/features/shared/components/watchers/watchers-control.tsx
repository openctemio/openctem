'use client'

/**
 * Watchers of a finding or a remediation task (RFC-120, research/256), as rows
 * of a People list (`<dl>`): one row with an avatar summary that opens the
 * manage sheet and your own Watch toggle, then the asset owners as context.
 *
 * Nothing on these rows removes anyone: removing happens only inside the
 * manage sheet, behind a labelled button, with an undo toast. The API decides
 * what the caller may see (names only with the member list, never emails) and
 * who may be added; `canAdd` and `canRemoveOthers` only hide what it refuses.
 * Watching grants no access.
 */

import { PropertyRow } from '@/features/shared/components/detail'
import { useSettleSignal } from '@/features/shared/components/settle-group'
import { useRef, useState } from 'react'
import { Bell, BellOff, ChevronRight, Loader2 } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { UserAvatar, UserAvatarStack } from '../user-avatar'
import type { WorkItemKind } from '../../api/use-participants'
import { ManageWatchersDialog, type WatcherPickerSource } from './manage-watchers-dialog'
import { useWatcherActions } from './use-watcher-actions'

export type { WatcherCandidate, WatcherPickerSource } from './manage-watchers-dialog'

export interface WatchersControlProps {
  kind: WorkItemKind
  itemId: string
  /** The caller may add people (the route's gate). */
  canAdd: boolean
  /** The caller may remove people other than themself. */
  canRemoveOthers: boolean
  /** Where the add search gets its candidates; without it nobody can be added. */
  picker?: WatcherPickerSource
}

export function WatchersControl({
  kind,
  itemId,
  canAdd,
  canRemoveOthers,
  picker,
}: WatchersControlProps) {
  const { t } = useTranslation()
  const { participants, isLoading, busy, setWatching, remove, add } = useWatcherActions(
    kind,
    itemId
  )
  useSettleSignal(isLoading)
  const [open, setOpen] = useState(false)
  const summaryRef = useRef<HTMLButtonElement>(null)

  if (isLoading || !participants) {
    return (
      <PropertyRow label={t('findings.people.watchers', 'Watchers')}>
        <span
          className="block h-control animate-pulse rounded-md bg-muted/50 max-md:h-control-touch"
          aria-busy="true"
          aria-label={t('findings.people.loading', 'Loading people')}
        />
      </PropertyRow>
    )
  }

  const watching = participants.me.state === 'subscribed'
  const count = participants.watcher_count
  const names = participants.names_visible ? participants.watchers.map((w) => w.name) : []
  const summary =
    count === 0
      ? t('findings.people.nobodyWatching', 'Nobody watching')
      : t('findings.people.watchingCount', '{count} watching', { count })

  const toggleLabel = watching
    ? kind === 'finding'
      ? t('findings.people.unwatchFinding', 'Stop watching this finding')
      : t('findings.people.unwatchTask', 'Stop watching this task')
    : kind === 'finding'
      ? t('findings.people.watchFinding', 'Watch this finding')
      : t('findings.people.watchTask', 'Watch this task')

  return (
    <>
      <PropertyRow label={t('findings.people.watchers', 'Watchers')}>
        {/* In a narrow rail the toggle wraps under the summary. */}
        <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 max-md:justify-end">
          <Button
            ref={summaryRef}
            type="button"
            variant="ghost"
            className="-ms-2 min-w-0 font-normal"
            onClick={() => setOpen(true)}
            aria-haspopup="dialog"
            data-testid="watchers-summary"
          >
            <UserAvatarStack names={names} />
            <span className="truncate">
              {summary}
              <span className="sr-only">
                {', '}
                {t('findings.people.manage', 'Manage watchers')}
              </span>
            </span>
            <ChevronRight className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          </Button>
          <Button
            type="button"
            variant={watching ? 'secondary' : 'outline'}
            disabled={busy}
            aria-label={toggleLabel}
            onClick={() => void setWatching(!watching)}
            data-testid="watch-toggle"
          >
            {busy ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : watching ? (
              <Bell className="size-4 fill-current" aria-hidden />
            ) : (
              <BellOff className="size-4" aria-hidden />
            )}
            {watching
              ? t('findings.people.watching', 'Watching')
              : t('findings.people.watch', 'Watch')}
          </Button>
        </span>
      </PropertyRow>

      {participants.names_visible && participants.asset_owners.length > 0 && (
        <PropertyRow label={t('findings.people.assetOwners', 'Asset owners')} top>
          <ul className="space-y-1 py-1">
            {participants.asset_owners.map((o) => (
              <li key={o.user_id} className="flex min-w-0 items-center gap-2">
                <UserAvatar name={o.name} />
                <span className="truncate">{o.name}</span>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {o.type === 'primary'
                    ? t('findings.people.ownerType.primary', 'primary')
                    : t('findings.people.ownerType.other', 'owner')}
                </span>
              </li>
            ))}
          </ul>
        </PropertyRow>
      )}

      <ManageWatchersDialog
        open={open}
        onOpenChange={setOpen}
        returnFocusRef={summaryRef}
        kind={kind}
        participants={participants}
        busy={busy}
        canAdd={canAdd}
        canRemoveOthers={canRemoveOthers}
        picker={picker}
        currentUserId={participants.me.user_id}
        onSetWatching={setWatching}
        onRemove={remove}
        onAdd={add}
      />
    </>
  )
}
