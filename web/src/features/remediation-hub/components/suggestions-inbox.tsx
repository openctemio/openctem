'use client'

/**
 * The suggestions inbox: proposals ranked by risk reduced, each explaining
 * why it was grouped. Review with the keyboard (j/k move, a accept, e edit,
 * d dismiss, s snooze, x select, ? why), or select several and accept them
 * in one go. Nothing changes until someone accepts.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
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
import type { DismissReason, RemediationSuggestion, SuggestionKind } from '../api/types'
import {
  type ApproveBody,
  hubApi,
  useRevalidateHub,
  useSuggestions,
} from '../api/use-remediation-hub'
import { isTypingTarget } from '../lib/hub'
import { SuggestionCard } from './suggestion-card'
import { AcceptDialog, DismissDialog } from './suggestion-dialogs'

const SNOOZE_DAYS = 7
const PER_PAGE = 25

export function apiMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiClientError && err.message) return err.message
  return fallback
}

export function SuggestionsInbox() {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
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
  const [busy, setBusy] = useState(false)
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
        toast.success(
          res.dropped.length
            ? `${msg} ${t('remediationHub.toast.dropped', undefined, { n: res.dropped.length })}`
            : msg
        )
        setEditing(null)
        await done()
      } catch (err) {
        toast.error(apiMessage(err, t('remediationHub.toast.failed')))
      } finally {
        setBusy(false)
      }
    },
    [done, t]
  )

  const dismiss = useCallback(
    async (s: RemediationSuggestion, reason: DismissReason, note: string) => {
      setBusy(true)
      try {
        const res = await hubApi.reject(s.id, { version: s.version, reason, note })
        setDismissing(null)
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
    [done, t]
  )

  const snooze = useCallback(
    async (s: RemediationSuggestion) => {
      const until = new Date(Date.now() + SNOOZE_DAYS * 24 * 3600 * 1000).toISOString()
      try {
        const res = await hubApi.snooze(s.id, { version: s.version, snoozed_until: until })
        await done()
        toast.success(t('remediationHub.toast.snoozed', undefined, { days: SNOOZE_DAYS }), {
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
      }
    },
    [done, t]
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
      if (editing || dismissing || e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target))
        return
      const s = items[active]
      switch (e.key) {
        case 'j':
          setActive((a) => Math.min(a + 1, items.length - 1))
          break
        case 'k':
          setActive((a) => Math.max(a - 1, 0))
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
          if (s && canWrite && s.hidden_members === 0) void snooze(s)
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
  }, [items, active, editing, dismissing, canWrite, canOwnerAccept, accept, snooze])

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
              onAccept={() => void accept(s)}
              onEdit={() => setEditing(s)}
              onDismiss={() => setDismissing(s)}
              onSnooze={() => void snooze(s)}
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
