'use client'

/**
 * Shown in the add dialogs when the organization already has the entry or
 * exclusion (409 SCOPE_ENTRY_EXISTS / SCOPE_EXCLUSION_EXISTS): what the
 * existing row is and the one thing to do about it, instead of "already
 * exists" with no way to find it.
 *
 * - pending: approve it (an approver who did not request it), or, where
 *   approvals are no longer required, put it in effect; Approvals opens the
 *   queue.
 * - inactive: activate it. expired (entries): renew it.
 * - rejected: remove the rejected row first (Show it opens it).
 * - active: Show it.
 *
 * The API decides each action again (permission, self-approval, step-up);
 * the buttons only offer what would not be refused.
 */

import { useState } from 'react'
import Link from '@/components/link'
import { safeHref } from '@/lib/safe-href'
import { Info, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useDisplayUser } from '@/hooks/use-display-user'
import { Permission, useHasPermission } from '@/lib/permissions'
import { ScopeActionConfirm, type ScopeConfirmKind } from './scope-action-confirm'
import {
  approveScopeTarget,
  decideScopeExclusion,
  invalidateScopeCache,
  setScopeExclusionActive,
  setScopeTargetActive,
  updateScopeTarget,
  useScopeSettingsApi,
  useScopeTargetApi,
} from '../api/use-scope-api'
import { SCOPE_EXISTING_TEXT, scopeErrorMessage, type ScopeDuplicate } from '../lib/scope-codes'
import { canApproveEntry } from '../lib/scope-entry'

const KNOWN = ['pending', 'active', 'inactive', 'expired', 'rejected'] as const

/** Where the existing row is listed: the tab, search and status filter. */
export function existingHref(dup: ScopeDuplicate, pattern: string): string {
  const q = new URLSearchParams({ tab: dup.kind === 'entry' ? 'in' : 'out', q: pattern })
  if (dup.kind === 'entry' && dup.status === 'rejected') q.set('status', 'rejected')
  return `/scope?${q.toString()}`
}

interface ScopeExistingNoticeProps {
  dup: ScopeDuplicate
  /** What was typed: the existing row has this pattern. */
  pattern: string
  /** After an action took effect (the dialog closes). */
  onDone: () => void
  /** Opens the existing row on this page; without it a link navigates. */
  onShow?: (href: string) => void
}

type Action = {
  key: string
  label: string
  fn: () => Promise<unknown>
  confirm: ScopeConfirmKind
}

export function ScopeExistingNotice({ dup, pattern, onDone, onShow }: ScopeExistingNoticeProps) {
  const { t } = useTranslation()
  const user = useDisplayUser()
  const canWrite = useHasPermission(Permission.ScopeWrite)
  const canApprove = useHasPermission(Permission.ScopeApprove)
  const canApproveExclusions = useHasPermission(Permission.ScopeExclusionsApprove)
  const { data: settings } = useScopeSettingsApi()
  const isEntry = dup.kind === 'entry'
  // The entry itself tells whether this user requested it (no self-approval).
  const { data: entry } = useScopeTargetApi(isEntry && dup.status === 'pending' ? dup.id : null)
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<Action | null>(null)

  // Unknown (still loading) counts as Strict.
  const needsApproval = settings?.approval_policy?.entries_need_approval ?? true
  const renewDays = settings?.one_off_max_days ?? 7
  const status = (KNOWN as readonly string[]).includes(dup.status) ? dup.status : 'unknown'
  const pendingOpen = status === 'pending' && !needsApproval

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true)
    try {
      await fn()
      await invalidateScopeCache()
      toast.success(t('scope.existing.done', '{pattern} updated', { pattern }))
      onDone()
    } catch (err) {
      toast.error(
        scopeErrorMessage(t, err, t('scope.existing.failed', 'The change was not saved.'))
      )
    } finally {
      setBusy(false)
    }
  }

  const actions: Action[] = []
  const activate = () =>
    isEntry ? setScopeTargetActive(dup.id, true) : setScopeExclusionActive(dup.id, true)
  if (pendingOpen && canWrite) {
    actions.push({
      key: 'effect',
      label: t('scope.existing.putInEffect', 'Put in effect'),
      fn: activate,
      confirm: 'activate',
    })
  } else if (
    status === 'pending' &&
    isEntry &&
    canApprove &&
    entry &&
    canApproveEntry(entry, user?.id)
  ) {
    actions.push({
      key: 'approve',
      label: t('scope.existing.approve', 'Approve'),
      fn: () => approveScopeTarget(dup.id),
      confirm: 'approve',
    })
  } else if (status === 'pending' && !isEntry && canApproveExclusions) {
    actions.push({
      key: 'approve',
      label: t('scope.existing.approve', 'Approve'),
      fn: () => decideScopeExclusion(dup.id, true),
      confirm: 'approve',
    })
  }
  if (status === 'inactive' && (isEntry ? canApprove || !needsApproval : canWrite)) {
    actions.push({
      key: 'activate',
      label: t('scope.existing.activate', 'Activate'),
      fn: activate,
      confirm: 'activate',
    })
  }
  if (status === 'expired' && isEntry && (canApprove || !needsApproval)) {
    actions.push({
      key: 'renew',
      label: t('scope.existing.renew', 'Renew for {n} days', { n: renewDays }),
      fn: () => updateScopeTarget(dup.id, { expires_in_days: renewDays }),
      confirm: 'renew',
    })
  }

  const href = existingHref(dup, pattern)
  const textKey = `${dup.kind}.${pendingOpen ? 'pendingOpen' : status}`

  return (
    <div
      role="alert"
      data-testid="scope-existing"
      data-status={status}
      className="space-y-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm"
    >
      <p className="flex items-start gap-2">
        <Info className="mt-0.5 h-4 w-4 shrink-0" />
        <span>{t(`scope.existing.${textKey}`, SCOPE_EXISTING_TEXT[textKey], { pattern })}</span>
      </p>
      <div className="flex flex-wrap items-center gap-2 ps-6">
        {actions.map((a) => (
          <Button
            key={a.key}
            type="button"
            size="sm"
            className="h-7 px-2 text-xs"
            disabled={busy}
            onClick={() => setPending(a)}
          >
            {busy && <Loader2 className="me-1 h-3 w-3 animate-spin" />}
            {a.label}
          </Button>
        ))}
        {onShow ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="h-7 px-2 text-xs"
            onClick={() => onShow(href)}
          >
            {t('scope.existing.show', 'Show it')}
          </Button>
        ) : (
          <Link href={safeHref(href) ?? '/scope'} className="text-xs underline underline-offset-2">
            {t('scope.existing.show', 'Show it')}
          </Link>
        )}
        {status === 'pending' && !pendingOpen && (
          <Link
            href="/scope?tab=approvals"
            className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground"
          >
            {t('scope.existing.openApprovals', 'Open approvals')}
          </Link>
        )}
      </div>
      <ScopeActionConfirm
        open={pending !== null}
        onOpenChange={(o) => !o && setPending(null)}
        kind={pending?.confirm ?? 'approve'}
        pattern={pattern}
        days={renewDays}
        isLoading={busy}
        onConfirm={async () => {
          const action = pending
          setPending(null)
          if (action) await run(action.fn)
        }}
      />
    </div>
  )
}
