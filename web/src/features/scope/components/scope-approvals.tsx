'use client'

/**
 * Scope › Approvals (research/53 §4.4, D8): every scope change waiting for a
 * second person, entries and exclusions in one list. Each card says who
 * asked, when, why, what it covers and for how long, and the approvals so
 * far. The requester sees their own changes with "waiting for another
 * approver"; approve is disabled with that reason instead of failing.
 *
 * Several changes can be approved at once: the server checks each one
 * (permission, not the requester, not twice) and asks for step-up on the
 * first; the re-authentication window then covers the rest.
 *
 * An entry also says who can still approve it (named for people who may see
 * the members, otherwise counted), how many approvals it still needs, and
 * offers "Remind approvers" (once an hour). When nobody else can approve it,
 * its owner-requester may approve it with a reason and an authenticator code
 * (RFC-054 §7).
 */

import { useMemo, useState } from 'react'
import { BellRing, Check, CheckCheck, Loader2, ShieldCheck, X } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ActorChip, EmptyState, RelativeTime, TonePill } from '@/features/shared'
import { useDisplayUser } from '@/hooks/use-display-user'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  approveScopeTarget,
  decideScopeExclusion,
  invalidateScopeCache,
  rejectScopeTarget,
  remindScopeApprovers,
  useScopeExclusionsApi,
  useScopeSettingsApi,
  useScopeTargetsApi,
} from '../api/use-scope-api'
import type { ApiScopeExclusion, ApiScopeTarget } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import { canApproveEntry, coversText, expiryText, TIER_LABEL } from '../lib/scope-entry'
import { scopeTargetTypeLabel } from './scope-target-type'
import { ScopeSelfApproveDialog } from './scope-self-approve-dialog'
import { ScopeAttestations } from './scope-attestations'

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** English with `{var}` filled: the default when no catalog is passed. */
const english: Translate = (_key, fallback = '', vars = {}) =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), fallback)

/** Who can still approve a pending entry, as one sentence. */
export function approversText(entry: ApiScopeTarget, t: Translate = english): string | null {
  const a = entry.approval
  if (!a) return null
  const left = a.remaining ?? 0
  const needs =
    left === 1
      ? t('scope.approvers.needs1', 'Needs 1 more approval')
      : t('scope.approvers.needsN', 'Needs {n} more approvals', { n: left })
  const count = a.eligible_approver_count ?? 0
  if (count === 0) {
    return `${needs}. ${t('scope.approvers.nobody', 'Nobody else in your organization can approve it.')}`
  }
  const names = (a.eligible_approvers ?? []).map((p) => p.name).filter(Boolean)
  if (names.length > 0) {
    return `${needs}. ${t('scope.approvers.names', 'Can approve: {names}.', { names: names.join(', ') })}`
  }
  return `${needs}. ${
    count === 1
      ? t('scope.approvers.count1', '1 member can approve it.')
      : t('scope.approvers.countN', '{n} members can approve it.', { n: count })
  }`
}

export function RemindButton({ entry }: { entry: ApiScopeTarget }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  // The API sends can_remind_at only while the next reminder is not due yet.
  const tooSoon = !!entry.approval?.can_remind_at
  if ((entry.approval?.eligible_approver_count ?? 0) === 0) return null
  return (
    <Button
      size="sm"
      variant="ghost"
      disabled={busy || tooSoon}
      title={tooSoon ? t('scope.error.REMINDER_TOO_SOON') : undefined}
      onClick={async () => {
        setBusy(true)
        try {
          const res = await remindScopeApprovers(entry.id ?? '')
          await invalidateScopeCache()
          toast.success(
            res?.reminded === 1
              ? t('scope.approvers.reminded1', 'Reminded 1 approver')
              : t('scope.approvers.remindedN', 'Reminded {n} approvers', { n: res?.reminded ?? 0 })
          )
        } catch (err) {
          toast.error(
            scopeErrorMessage(
              t,
              err,
              t('scope.approvers.remindFailed', 'Could not send the reminder.')
            )
          )
        } finally {
          setBusy(false)
        }
      }}
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <BellRing className="h-4 w-4" />}
      {t('scope.approvers.remind', 'Remind approvers')}
    </Button>
  )
}

export type PendingChange =
  | { kind: 'entry'; id: string; item: ApiScopeTarget }
  | { kind: 'exclusion'; id: string; item: ApiScopeExclusion }

/** Why the caller may not approve a change, or null when they may. */
export function approveBlocker(
  c: PendingChange,
  userId: string | undefined,
  perms: { entries: boolean; exclusions: boolean }
): string | null {
  if (c.kind === 'entry') {
    if (!perms.entries) return 'Only a scope approver can approve scope entries.'
    if (c.item.created_by?.id === userId)
      return 'You requested this; another approver must approve it.'
    if (!canApproveEntry(c.item, userId))
      return 'You already approved this; it waits for another approver.'
    return null
  }
  if (!perms.exclusions) return 'Only an exclusion approver can approve exclusions.'
  if (c.item.created_by?.id === userId)
    return 'You requested this; another approver must approve it.'
  return null
}

function isEntryKind(c: PendingChange): boolean {
  return c.kind === 'entry'
}

export function usePendingScopeChanges() {
  const entries = useScopeTargetsApi({ status: 'pending', per_page: 100 })
  const exclusions = useScopeExclusionsApi({ status: 'pending', per_page: 100 })
  const changes = useMemo<PendingChange[]>(() => {
    const out: PendingChange[] = [
      ...(entries.data?.data ?? []).map((item) => ({
        kind: 'entry' as const,
        id: item.id ?? '',
        item,
      })),
      ...(exclusions.data?.data ?? []).map((item) => ({
        kind: 'exclusion' as const,
        id: item.id ?? '',
        item,
      })),
    ]
    // Oldest first: the change that has waited longest is decided first.
    return out.sort((a, b) => (a.item.created_at ?? '').localeCompare(b.item.created_at ?? ''))
  }, [entries.data, exclusions.data])
  const total = (entries.data?.total ?? 0) + (exclusions.data?.total ?? 0)
  return { changes, total, isLoading: entries.isLoading || exclusions.isLoading }
}

export function ScopeApprovals() {
  const { t } = useTranslation()
  const user = useDisplayUser()
  const perms = {
    entries: useHasPermission(Permission.ScopeApprove),
    exclusions: useHasPermission(Permission.ScopeExclusionsApprove),
  }
  const { data: settings } = useScopeSettingsApi()
  const canWrite = useHasPermission(Permission.ScopeWrite)
  const { changes, isLoading } = usePendingScopeChanges()
  const [selfApprove, setSelfApprove] = useState<ApiScopeTarget | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)

  const decide = async (list: PendingChange[], approve: boolean) => {
    setBusy(true)
    let done = 0
    for (const c of list) {
      try {
        if (c.kind === 'entry') {
          await (approve ? approveScopeTarget(c.id) : rejectScopeTarget(c.id))
        } else {
          await decideScopeExclusion(c.id, approve)
        }
        done += 1
      } catch (err) {
        toast.error(`${c.item.pattern}: ${scopeErrorMessage(t, err, 'not saved')}`)
      }
    }
    await invalidateScopeCache()
    setSelected(new Set())
    setBusy(false)
    if (done > 0)
      toast.success(
        `${done} ${done === 1 ? 'change' : 'changes'} ${approve ? 'approved' : 'rejected'}`
      )
  }

  if (isLoading && changes.length === 0) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-28 w-full rounded-lg" />
        <Skeleton className="h-28 w-full rounded-lg" />
      </div>
    )
  }

  if (changes.length === 0) {
    const n = settings?.effective_widening_approvals ?? 0
    return (
      <div className="space-y-6">
        <ScopeAttestations />
        <EmptyState
          icon={CheckCheck}
          title="No changes wait for approval"
          description={
            settings?.approval_policy?.mode === 'disabled'
              ? 'Approvals are disabled by your platform administrator: changes that widen scope take effect at once.'
              : n > 0
                ? `Your organization requires ${n} ${n === 1 ? 'approval' : 'approvals'} for changes that widen scope (Scope policy).`
                : 'Changes that widen scope take effect at once in your organization (Scope policy).'
          }
        />
      </div>
    )
  }

  const decidable = changes.filter((c) => !approveBlocker(c, user?.id, perms))
  const chosen = decidable.filter((c) => selected.has(`${c.kind}:${c.id}`))

  return (
    <div className="space-y-3">
      <ScopeAttestations />
      {decidable.length > 1 && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Checkbox
            id="approve-all"
            checked={chosen.length === decidable.length}
            onCheckedChange={(v) =>
              setSelected(v ? new Set(decidable.map((c) => `${c.kind}:${c.id}`)) : new Set())
            }
            aria-label="Select every change you may approve"
          />
          <label htmlFor="approve-all">Select all you may approve ({decidable.length})</label>
          <Button
            size="sm"
            className="ms-auto"
            disabled={busy || chosen.length === 0}
            onClick={() => void decide(chosen, true)}
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
            Approve selected ({chosen.length})
          </Button>
        </div>
      )}
      <ul className="space-y-3" aria-label="Changes waiting for approval">
        {changes.map((c) => {
          const key = `${c.kind}:${c.id}`
          const blocker = approveBlocker(c, user?.id, perms)
          const mayDecide = isEntryKind(c) ? perms.entries : perms.exclusions
          const isEntry = c.kind === 'entry'
          const e = c.item
          const approvals = isEntry ? (c.item.approvals ?? []) : []
          const required = isEntry ? (c.item.approvals_required ?? 1) : 1
          return (
            <li key={key} className="space-y-3 rounded-lg border p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
                {!blocker && decidable.length > 1 && (
                  <Checkbox
                    checked={selected.has(key)}
                    onCheckedChange={(v) => {
                      const next = new Set(selected)
                      if (v) next.add(key)
                      else next.delete(key)
                      setSelected(next)
                    }}
                    aria-label={`Select ${e.pattern}`}
                    className="mt-1"
                  />
                )}
                <div className="min-w-0 flex-1 space-y-1 break-words">
                  <div className="flex flex-wrap items-center gap-2">
                    <TonePill
                      tone={isEntry ? 'info' : 'muted'}
                      label={isEntry ? 'Adds to scope' : 'Puts out of scope'}
                    />
                    <code className="break-all text-sm font-medium">{e.pattern}</code>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {isEntry
                      ? `Covers ${coversText(c.item)} · ${scopeTargetTypeLabel(c.item.target_type ?? '')} · ${TIER_LABEL[c.item.max_tier ?? 't1'] ?? ''} · ${c.item.expires_at ? expiryText(c.item.expires_at) : 'permanent'}`
                      : `Scans would never touch ${coversText({ pattern: c.item.pattern, target_type: c.item.exclusion_type })}${c.item.expires_at ? ` · ${expiryText(c.item.expires_at).toLowerCase()}` : ''}`}
                  </p>
                  {e.reason && <p className="text-sm">&ldquo;{e.reason}&rdquo;</p>}
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                    <span className="inline-flex items-center gap-1">
                      Asked by <ActorChip actor={e.created_by} compact />
                    </span>
                    {e.created_at && <RelativeTime date={e.created_at} />}
                    {isEntry && (
                      <span>
                        {approvals.length} of {required} approvals
                      </span>
                    )}
                    {approvals.map((a) => (
                      <span key={a.user_id} className="inline-flex items-center gap-1">
                        approved by <ActorChip actor={a.user_id} at={a.approved_at} compact />
                      </span>
                    ))}
                  </div>
                  {isEntry && approversText(c.item, t) && (
                    <p className="text-xs text-muted-foreground" data-testid="approvers-line">
                      {approversText(c.item, t)}
                    </p>
                  )}
                  {isEntry && (canWrite || c.item.approval?.self_approval_available) && (
                    <div className="flex flex-wrap gap-2 pt-1">
                      {canWrite && <RemindButton entry={c.item} />}
                      {c.item.approval?.self_approval_available && (
                        <Button size="sm" variant="outline" onClick={() => setSelfApprove(c.item)}>
                          <ShieldCheck className="h-4 w-4" />
                          Approve as the only owner
                        </Button>
                      )}
                    </div>
                  )}
                </div>
                {mayDecide ? (
                  <div className="flex shrink-0 flex-col gap-1 sm:items-end">
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        disabled={busy || !!blocker}
                        onClick={() => void decide([c], true)}
                        aria-describedby={blocker ? `${key}-why` : undefined}
                      >
                        <Check className="h-4 w-4" />
                        Approve
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy || e.created_by?.id === user?.id}
                        onClick={() => void decide([c], false)}
                      >
                        <X className="h-4 w-4" />
                        Reject
                      </Button>
                    </div>
                    {blocker && (
                      <p
                        id={`${key}-why`}
                        className="text-xs text-muted-foreground sm:max-w-56 sm:text-end"
                      >
                        {blocker}
                      </p>
                    )}
                  </div>
                ) : (
                  // Without the approve permission there is nothing to click:
                  // say where it stands instead of showing dead buttons.
                  <p className="shrink-0 text-xs text-muted-foreground sm:max-w-56 sm:text-end">
                    {e.created_by?.id === user?.id
                      ? 'You asked for this. It waits for an approver.'
                      : 'Waiting for an approver.'}
                  </p>
                )}
              </div>
            </li>
          )
        })}
      </ul>
      {selfApprove && (
        <ScopeSelfApproveDialog entry={selfApprove} onOpenChange={() => setSelfApprove(null)} />
      )}
    </div>
  )
}
