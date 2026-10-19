'use client'

/**
 * The suggestions inbox: proposals ranked by risk reduced, each explaining
 * why it was grouped. Review with the keyboard (j/k move, Enter or o open the
 * detail panel, a accept, e edit, d dismiss, s snooze, x select, ? why), or
 * select several and accept them in one go. The panel is a deep link
 * (?suggestion=<id>); Esc closes it. Findings another task took since the
 * suggestion was made are skipped or moved only as the person decides.
 * Nothing changes until someone accepts.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Inbox, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { ApiClientError } from '@/lib/api/error-handler'
import type {
  DismissReason,
  FindingConflict,
  RemediationSuggestion,
  SuggestionKind,
} from '../api/types'
import {
  type ApproveBody,
  hubApi,
  useRevalidateHub,
  useSuggestion,
  useSuggestions,
} from '../api/use-remediation-hub'
import { isTypingTarget } from '../lib/hub'
import { claimConflicts, suggestionParam } from '../lib/suggestion-detail'
import { ConflictDialog } from './conflict-dialog'
import { SuggestionCard } from './suggestion-card'
import { SuggestionPanel } from './suggestion-panel'
import { AcceptDialog, DismissDialog, SnoozeDialog } from './suggestion-dialogs'

const PER_PAGE = 25

export function apiMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiClientError && err.message) return err.message
  return fallback
}

export function SuggestionsInbox() {
  const { t, locale } = useTranslation()
  const { hasPermission } = usePermissions()
  const router = useRouter()
  const params = useSearchParams()
  const openId = suggestionParam(params?.get('suggestion'))
  const canWrite = hasPermission(Permission.RemediationWrite)
  // Asset owners without write access may accept a join into their task or a
  // new task for them, as it is; the API checks ownership and scope.
  const canOwnerAccept = useCallback(
    (s: RemediationSuggestion) =>
      !canWrite &&
      hasPermission(Permission.RemediationRead) &&
      (s.kind === 'join' || s.kind === 'task_route'),
    [canWrite, hasPermission]
  )
  const revalidate = useRevalidateHub()
  const [kind, setKind] = useState<SuggestionKind | 'all'>('all')
  const [keyKind, setKeyKind] = useState<string>('all')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const { data, error, isLoading, mutate } = useSuggestions({
    kinds: kind === 'all' ? undefined : [kind],
    keyKind: keyKind === 'all' ? undefined : keyKind,
    search,
    page,
    perPage: PER_PAGE,
  })
  const items = useMemo(() => data?.data ?? [], [data])
  const [active, setActive] = useState(0)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [explain, setExplain] = useState<string | null>(null)
  const [editing, setEditing] = useState<RemediationSuggestion | null>(null)
  const [dismissing, setDismissing] = useState<RemediationSuggestion | null>(null)
  const [snoozing, setSnoozing] = useState<RemediationSuggestion | null>(null)
  const [conflict, setConflict] = useState<{
    s: RemediationSuggestion
    body: Omit<ApproveBody, 'version'>
    conflicts: FindingConflict[]
  } | null>(null)
  const [busy, setBusy] = useState(false)
  // The panel's suggestion: from the page when it is there, else by id.
  const onPage = openId ? items.find((x) => x.id === openId) : undefined
  const { data: byId, isLoading: byIdLoading } = useSuggestion(
    openId && !onPage ? openId : undefined
  )
  const panelSuggestion = onPage ?? byId ?? null
  const panelIndex = onPage ? items.indexOf(onPage) : -1

  const setOpenId = useCallback(
    (id: string | undefined) => {
      const next = new URLSearchParams(params?.toString() ?? '')
      if (id) next.set('suggestion', id)
      else next.delete('suggestion')
      const qs = next.toString()
      router.replace(qs ? `?${qs}` : '?', { scroll: false })
    },
    [params, router]
  )
  const cardRefs = useRef<(HTMLDivElement | null)[]>([])

  useEffect(() => {
    setActive((a) => Math.min(a, Math.max(items.length - 1, 0)))
  }, [items.length])

  const done = useCallback(async () => {
    await Promise.all([mutate(), revalidate()])
  }, [mutate, revalidate])

  const accept = useCallback(
    async (s: RemediationSuggestion, body: Omit<ApproveBody, 'version'> = {}) => {
      setBusy(true)
      try {
        const res = await hubApi.approve(s.id, { version: s.version, ...body })
        const msg =
          res.joined > 0
            ? t('remediationHub.toast.joined', undefined, { n: res.joined })
            : t('remediationHub.toast.accepted', undefined, { n: res.task_ids.length })
        const extra = [
          res.dropped.length
            ? t('remediationHub.toast.dropped', undefined, { n: res.dropped.length })
            : '',
          res.skipped?.length
            ? t('remediationHub.toast.skipped', undefined, { n: res.skipped.length })
            : '',
          res.moved ? t('remediationHub.toast.movedFrom', undefined, { n: res.moved }) : '',
        ].filter(Boolean)
        toast.success([msg, ...extra].join(' '))
        setEditing(null)
        setConflict(null)
        if (openId === s.id) setOpenId(undefined)
        await done()
      } catch (err) {
        const conflicts = claimConflicts(err)
        if (conflicts && conflicts.length > 0) {
          // Another task took some findings since: the person decides.
          setEditing(null)
          setConflict({ s, body, conflicts })
        } else {
          toast.error(apiMessage(err, t('remediationHub.toast.failed')))
        }
      } finally {
        setBusy(false)
      }
    },
    [done, t, openId, setOpenId]
  )

  const dismiss = useCallback(
    async (s: RemediationSuggestion, reason: DismissReason, note: string) => {
      setBusy(true)
      try {
        const res = await hubApi.reject(s.id, { version: s.version, reason, note })
        setDismissing(null)
        if (openId === s.id) setOpenId(undefined)
        await done()
        toast.success(t('remediationHub.toast.dismissed'), {
          action: {
            label: t('remediationHub.actions.undo'),
            onClick: () => {
              void hubApi
                .reopen(s.id, res.version)
                .then(done, (err) => toast.error(apiMessage(err, t('remediationHub.toast.failed'))))
            },
          },
        })
      } catch (err) {
        toast.error(apiMessage(err, t('remediationHub.toast.failed')))
      } finally {
        setBusy(false)
      }
    },
    [done, t, openId, setOpenId]
  )

  const snooze = useCallback(
    async (s: RemediationSuggestion, until: string) => {
      setBusy(true)
      try {
        const res = await hubApi.snooze(s.id, { version: s.version, snoozed_until: until })
        setSnoozing(null)
        if (openId === s.id) setOpenId(undefined)
        await done()
        toast.success(
          t('remediationHub.toast.snoozedUntil', undefined, {
            date: new Date(until).toLocaleDateString(locale, { dateStyle: 'medium' }),
          }),
          {
            action: {
              label: t('remediationHub.actions.undo'),
              onClick: () => {
                void hubApi
                  .reopen(s.id, res.version)
                  .then(done, (err) =>
                    toast.error(apiMessage(err, t('remediationHub.toast.failed')))
                  )
              },
            },
          }
        )
      } catch (err) {
        toast.error(apiMessage(err, t('remediationHub.toast.failed')))
      } finally {
        setBusy(false)
      }
    },
    [done, t, locale, openId, setOpenId]
  )

  const bulkAccept = useCallback(async () => {
    setBusy(true)
    try {
      const res = await hubApi.bulkApprove([...selected])
      const ok = res.filter((r) => !r.error).length
      const failed = res.length - ok
      if (failed) toast.warning(t('remediationHub.toast.bulkPartial', undefined, { ok, failed }))
      else toast.success(t('remediationHub.toast.bulkAccepted', undefined, { n: ok }))
      setSelected(new Set())
      await done()
    } catch (err) {
      toast.error(apiMessage(err, t('remediationHub.toast.failed')))
    } finally {
      setBusy(false)
    }
  }, [done, selected, t])

  const runNow = useCallback(async () => {
    try {
      const st = await hubApi.runNow()
      toast.success(
        t('remediationHub.toast.refreshed', undefined, {
          created: st.created ?? 0,
          updated: st.updated ?? 0,
        })
      )
      await done()
    } catch (err) {
      toast.error(apiMessage(err, t('remediationHub.toast.failed')))
    }
  }, [done, t])

  // Keyboard review: only when no dialog is open and nobody is typing.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (
        editing ||
        dismissing ||
        snoozing ||
        conflict ||
        e.metaKey ||
        e.ctrlKey ||
        e.altKey ||
        isTypingTarget(e.target)
      )
        return
      const s = openId ? panelSuggestion : items[active]
      const move = (step: number) => {
        const next = Math.min(Math.max(active + step, 0), items.length - 1)
        setActive(next)
        if (openId && items[next]) setOpenId(items[next].id)
      }
      switch (e.key) {
        case 'j':
          move(1)
          break
        case 'k':
          move(-1)
          break
        case 'Enter':
        case 'o':
          if (openId || !items[active]) return
          // Enter on a button or link inside a card keeps its own meaning.
          if (e.key === 'Enter' && e.target instanceof HTMLElement && e.target.closest('button, a'))
            return
          setOpenId(items[active].id)
          break
        case 'a':
          if (s && (canWrite || canOwnerAccept(s)) && s.hidden_members === 0) void accept(s)
          break
        case 'e':
          if (s && canWrite && s.hidden_members === 0) setEditing(s)
          break
        case 'd':
          if (s && canWrite && s.hidden_members === 0) setDismissing(s)
          break
        case 's':
          if (s && canWrite && s.hidden_members === 0) setSnoozing(s)
          break
        case 'x':
          if (s && canWrite && s.hidden_members === 0)
            setSelected((cur) => {
              const n = new Set(cur)
              if (n.has(s.id)) n.delete(s.id)
              else n.add(s.id)
              return n
            })
          break
        case '?':
          if (s) setExplain((x) => (x === s.id ? null : s.id))
          break
        default:
          return
      }
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [
    items,
    active,
    editing,
    dismissing,
    snoozing,
    conflict,
    canWrite,
    canOwnerAccept,
    accept,
    openId,
    panelSuggestion,
    setOpenId,
  ])

  useEffect(() => {
    const el = cardRefs.current[active]
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'nearest' })
  }, [active])

  const pages = data ? Math.max(1, Math.ceil(data.total / PER_PAGE)) : 1

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="w-full sm:w-64"
          placeholder={t('remediationHub.suggestions.search')}
          aria-label={t('remediationHub.suggestions.search')}
          value={search}
          onChange={(e) => {
            setSearch(e.target.value)
            setPage(1)
          }}
        />
        <Select
          value={kind}
          onValueChange={(v) => {
            setKind(v as SuggestionKind | 'all')
            setPage(1)
          }}
        >
          <SelectTrigger
            className="w-full sm:w-44"
            aria-label={t('remediationHub.suggestions.kindFilter')}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('remediationHub.suggestions.allKinds')}</SelectItem>
            {(['new_group', 'join', 'task_route'] as const).map((k) => (
              <SelectItem key={k} value={k}>
                {t(`remediationHub.kind.${k}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={keyKind}
          onValueChange={(v) => {
            setKeyKind(v)
            setPage(1)
          }}
        >
          <SelectTrigger
            className="w-full sm:w-44"
            aria-label={t('remediationHub.suggestions.keyKindFilter')}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('remediationHub.suggestions.allFixes')}</SelectItem>
            {['upgrade', 'rotate', 'sol'].map((k) => (
              <SelectItem key={k} value={k}>
                {t(`remediationHub.keyKind.${k}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ms-auto flex flex-wrap items-center gap-2">
          {canWrite && selected.size > 0 && (
            <Button onClick={bulkAccept} disabled={busy}>
              {t('remediationHub.suggestions.acceptSelected', undefined, { n: selected.size })}
            </Button>
          )}
          {canWrite && (
            <Button variant="outline" onClick={runNow}>
              <RefreshCw className="size-4" aria-hidden />
              {t('remediationHub.suggestions.runNow')}
            </Button>
          )}
        </div>
      </div>
      <p className="text-muted-foreground text-xs" aria-live="polite">
        {t(canWrite ? 'remediationHub.suggestions.keys' : 'remediationHub.suggestions.keysOwner')}
      </p>

      {error ? (
        <ErrorState
          title={t('remediationHub.suggestions.loadError')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : isLoading && !data ? (
        <div className="space-y-3" aria-busy="true">
          {Array.from({ length: 3 }, (_, i) => (
            <Skeleton key={i} className="h-32 w-full" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={Inbox}
          title={t('remediationHub.suggestions.emptyTitle')}
          description={t('remediationHub.suggestions.emptyDescription')}
          card
        />
      ) : (
        <div className="space-y-3">
          {items.map((s, i) => (
            <SuggestionCard
              key={s.id}
              ref={(el) => {
                cardRefs.current[i] = el
              }}
              suggestion={s}
              active={i === active}
              selected={selected.has(s.id)}
              canWrite={canWrite}
              canOwnerAccept={canOwnerAccept(s)}
              onSelect={(v) =>
                setSelected((cur) => {
                  const n = new Set(cur)
                  if (v) n.add(s.id)
                  else n.delete(s.id)
                  return n
                })
              }
              onFocus={() => setActive(i)}
              onOpen={() => {
                setActive(i)
                setOpenId(s.id)
              }}
              onAccept={() => void accept(s)}
              onEdit={() => setEditing(s)}
              onDismiss={() => setDismissing(s)}
              onSnooze={() => setSnoozing(s)}
              explainOpen={explain === s.id}
              onToggleExplain={() => setExplain((x) => (x === s.id ? null : s.id))}
            />
          ))}
          {pages > 1 && (
            <div className="flex items-center justify-end gap-2 text-sm">
              <Button
                size="sm"
                variant="ghost"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                {t('remediationHub.actions.previous')}
              </Button>
              <span>{t('remediationHub.pageOf', undefined, { page, pages })}</span>
              <Button
                size="sm"
                variant="ghost"
                disabled={page >= pages}
                onClick={() => setPage((p) => p + 1)}
              >
                {t('remediationHub.actions.next')}
              </Button>
            </div>
          )}
        </div>
      )}

      <AcceptDialog
        suggestion={editing}
        open={editing !== null}
        onOpenChange={(o) => !o && setEditing(null)}
        onConfirm={(body) => editing && void accept(editing, body)}
        busy={busy}
        canAutoJoin={canWrite}
      />
      <SuggestionPanel
        suggestion={panelSuggestion}
        loading={byIdLoading}
        open={openId !== undefined}
        onOpenChange={(o) => !o && setOpenId(undefined)}
        canWrite={canWrite}
        canOwnerAccept={panelSuggestion ? canOwnerAccept(panelSuggestion) : false}
        busy={busy}
        onAccept={(body) => panelSuggestion && void accept(panelSuggestion, body)}
        onEdit={() => panelSuggestion && setEditing(panelSuggestion)}
        onDismiss={() => panelSuggestion && setDismissing(panelSuggestion)}
        onSnooze={() => panelSuggestion && setSnoozing(panelSuggestion)}
        position={panelIndex >= 0 ? { index: panelIndex, total: items.length } : undefined}
        onPrev={
          panelIndex > 0
            ? () => {
                setActive(panelIndex - 1)
                setOpenId(items[panelIndex - 1].id)
              }
            : undefined
        }
        onNext={
          panelIndex >= 0 && panelIndex < items.length - 1
            ? () => {
                setActive(panelIndex + 1)
                setOpenId(items[panelIndex + 1].id)
              }
            : undefined
        }
      />
      <SnoozeDialog
        suggestion={snoozing}
        open={snoozing !== null}
        onOpenChange={(o) => !o && setSnoozing(null)}
        onConfirm={(until) => snoozing && void snooze(snoozing, until)}
        busy={busy}
      />
      <ConflictDialog
        conflicts={conflict?.conflicts ?? []}
        open={conflict !== null}
        onOpenChange={(o) => !o && setConflict(null)}
        onResolve={(r) => conflict && void accept(conflict.s, { ...conflict.body, conflicts: r })}
        busy={busy}
      />
      <DismissDialog
        suggestion={dismissing}
        open={dismissing !== null}
        onOpenChange={(o) => !o && setDismissing(null)}
        onConfirm={(reason, note) => dismissing && void dismiss(dismissing, reason, note)}
        busy={busy}
      />
    </div>
  )
}
