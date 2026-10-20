'use client'

/**
 * The People section's watchers part (RFC-120): who watches a finding or a
 * task, with why each person does, an add control for those who may, the bell
 * for yourself, and the owners of the finding's asset as context. The API
 * answers what the caller may see: without the member list (viewers, pentest
 * clients) there are no names, only the count, and the bell still works.
 * Watching grants no access: the add picker lists only people the API says
 * can read the item.
 */

import { useState } from 'react'
import { Plus, X } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { useParticipants, type WatcherReason, type WorkItemKind } from '../api/use-participants'
import { WatchToggle } from './watch-toggle'

export interface WatcherCandidate {
  id: string
  name: string
}

export interface WatcherPickerSource {
  candidates: WatcherCandidate[]
  isLoading: boolean
  onSearch: (query: string) => void
  /** The caller starts loading candidates when it opens. */
  onOpenChange: (open: boolean) => void
}

export interface WatchersBlockProps {
  kind: WorkItemKind
  itemId: string
  /** The caller may add people (the route's gate). Hidden otherwise. */
  canAdd: boolean
  /** The caller may remove people other than themself. */
  canRemoveOthers: boolean
  /** Where the add picker gets its candidates; without it nobody can be added. */
  picker?: WatcherPickerSource
  currentUserId?: string
}

function initials(name: string): string {
  return (
    name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2) || '?'
  )
}

export function WatchersBlock({
  kind,
  itemId,
  canAdd,
  canRemoveOthers,
  picker,
  currentUserId,
}: WatchersBlockProps) {
  const { t } = useTranslation()
  const { participants, isLoading, busy, setWatching, addWatchers, removeWatcher } =
    useParticipants(kind, itemId)
  const [open, setOpen] = useState(false)

  const reasonLabel = (reason: WatcherReason): string => {
    switch (reason) {
      case 'manual':
        return t('findings.people.reason.manual', 'chose to watch')
      case 'added':
        return t('findings.people.reason.added', 'added')
      case 'assigned':
        return t('findings.people.reason.assigned', 'was assigned')
      case 'commented':
        return t('findings.people.reason.commented', 'commented')
      case 'status_changed':
        return t('findings.people.reason.status_changed', 'changed the status')
      case 'fix_claimed':
        return t('findings.people.reason.fix_claimed', 'claimed the fix')
      case 'mentioned':
        return t('findings.people.reason.mentioned', 'was mentioned')
      case 'approval':
        return t('findings.people.reason.approval', 'took part in an approval')
      case 'created':
        return t('findings.people.reason.created', 'created it')
    }
  }

  if (isLoading || !participants) {
    return (
      <div
        className="h-16 animate-pulse rounded-md bg-muted/50"
        aria-busy="true"
        aria-label={t('findings.people.loading', 'Loading people')}
      />
    )
  }

  const watching = participants.me.state === 'subscribed'
  const watcherIds = new Set(participants.watchers.map((w) => w.user_id))
  const candidates = (picker?.candidates ?? []).filter((c) => !watcherIds.has(c.id))
  const showAdd = canAdd && !!picker

  return (
    <div className="space-y-3">
      <div className="space-y-1.5">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-muted-foreground">
            {t('findings.people.watchers', 'Watchers')}
            <span className="ms-1 tabular-nums">{participants.watcher_count}</span>
          </span>
          {showAdd && (
            <Popover
              open={open}
              onOpenChange={(next) => {
                setOpen(next)
                picker?.onOpenChange(next)
              }}
            >
              <PopoverTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1 px-1.5 text-xs"
                  disabled={busy}
                >
                  <Plus className="h-3 w-3" aria-hidden />
                  {t('findings.people.add', 'Add')}
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-56 p-0" align="end">
                <Command shouldFilter={false}>
                  <CommandInput
                    placeholder={t('findings.people.search', 'Search people...')}
                    onValueChange={(q) => picker?.onSearch(q)}
                  />
                  <CommandList>
                    {!picker?.isLoading && candidates.length === 0 && (
                      <CommandEmpty>
                        {t('findings.people.noCandidates', 'Nobody to add.')}
                      </CommandEmpty>
                    )}
                    <CommandGroup>
                      {candidates.map((c) => (
                        <CommandItem
                          key={c.id}
                          value={c.id}
                          onSelect={async () => {
                            if (await addWatchers([c.id])) setOpen(false)
                          }}
                        >
                          <Avatar className="me-2 h-5 w-5">
                            <AvatarFallback className="text-[10px]">
                              {initials(c.name)}
                            </AvatarFallback>
                          </Avatar>
                          <span className="truncate">{c.name}</span>
                        </CommandItem>
                      ))}
                    </CommandGroup>
                    <p className="px-2 py-1.5 text-xs text-muted-foreground">
                      {t('findings.people.onlyReaders', 'Only people who can see this are listed.')}
                    </p>
                  </CommandList>
                </Command>
              </PopoverContent>
            </Popover>
          )}
        </div>

        {participants.names_visible ? (
          participants.watchers.length > 0 ? (
            <ul className="space-y-1" aria-label={t('findings.people.watchers', 'Watchers')}>
              {participants.watchers.map((w) => {
                const mine = w.user_id === currentUserId
                const canRemove = mine || canRemoveOthers
                return (
                  <li key={w.user_id} className="flex items-center gap-2 text-sm">
                    <Avatar className="h-5 w-5 shrink-0">
                      <AvatarFallback className="text-[10px]">{initials(w.name)}</AvatarFallback>
                    </Avatar>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate">{w.name}</span>
                      <Badge variant="secondary" className="px-1 py-0 text-[10px] font-normal">
                        {reasonLabel(w.reason)}
                      </Badge>
                    </span>
                    {canRemove && (
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6 shrink-0"
                        disabled={busy}
                        aria-label={t('findings.people.remove', 'Remove {name}', { name: w.name })}
                        onClick={() => void removeWatcher(w.user_id)}
                      >
                        <X className="h-3 w-3" aria-hidden />
                      </Button>
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
          <p className="text-xs text-muted-foreground">
            {t(
              'findings.people.namesHidden',
              'Names are shown to people who can see the member list.'
            )}
          </p>
        )}
      </div>

      {participants.names_visible && participants.asset_owners.length > 0 && (
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">
            {t('findings.people.assetOwners', 'Asset owners')}
          </span>
          <ul className="space-y-1">
            {participants.asset_owners.map((o) => (
              <li key={o.user_id} className="flex items-center gap-2 text-sm">
                <Avatar className="h-5 w-5 shrink-0">
                  <AvatarFallback className="text-[10px]">{initials(o.name)}</AvatarFallback>
                </Avatar>
                <span className="truncate">{o.name}</span>
                <span className="text-xs text-muted-foreground">
                  {o.type === 'primary'
                    ? t('findings.people.ownerType.primary', 'primary')
                    : t('findings.people.ownerType.other', 'owner')}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <WatchToggle
        watching={watching}
        busy={busy}
        onChange={(next) => void setWatching(next)}
        labels={{
          watching: t('findings.people.watching', 'Watching'),
          notWatching: t('findings.people.notWatching', 'Not watching'),
          hintWatching:
            kind === 'finding'
              ? t('findings.people.hintWatchingFinding', 'You get updates on this finding.')
              : t('findings.people.hintWatchingTask', 'You get updates on this task.'),
          hintNotWatching:
            kind === 'finding'
              ? t(
                  'findings.people.hintNotWatchingFinding',
                  'Watch it to get updates on this finding.'
                )
              : t('findings.people.hintNotWatchingTask', 'Watch it to get updates on this task.'),
        }}
      />
    </div>
  )
}
