'use client'

/**
 * Edit a scope entry (RFC-054 §6.1, PUT /scope/targets/{id}). Type and
 * pattern identify the entry and never change. A later or removed expiry, or
 * a higher tier, widens it: that needs a scope approver and step-up, and the
 * entry may go back to "pending" until it is approved again, authorizing
 * nothing meanwhile. The dialog says so before the click.
 */

import { useEffect, useId, useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, useHasPermission } from '@/lib/permissions'
import { invalidateScopeCache, updateScopeTarget, useScopeSettingsApi } from '../api/use-scope-api'
import type { ApiScopeTarget, ScopeTier, UpdateScopeTargetInput } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import {
  coversText,
  daysUntil,
  durationPolicy,
  expiryText,
  resolveDuration,
  TIER_HINT,
  TIER_LABEL,
  TIER_TOOLS,
  type DurationChoice,
  type DurationPolicy,
} from '../lib/scope-entry'
import { ScopeDurationField } from './scope-duration-field'

const TIER_RANK: Record<string, number> = { t0: 0, t1: 1, t2: 2 }

/** Whether the change widens the entry (a later/removed expiry, a higher tier). */
export function isWideningChange(entry: ApiScopeTarget, change: UpdateScopeTargetInput): boolean {
  if (change.max_tier && TIER_RANK[change.max_tier] > TIER_RANK[entry.max_tier ?? 't1']) return true
  if (change.clear_expiry && entry.expires_at) return true
  if (change.expires_in_days !== undefined) {
    if (!entry.expires_at) return false // a permanent entry getting an expiry narrows
    return change.expires_in_days > daysUntil(entry.expires_at)
  }
  return false
}

interface ScopeEntryEditDialogProps {
  entry: ApiScopeTarget | null
  onOpenChange: (open: boolean) => void
}

export function ScopeEntryEditDialog({ entry, onOpenChange }: ScopeEntryEditDialogProps) {
  const { t } = useTranslation()
  const formId = useId()
  const canApprove = useHasPermission(Permission.ScopeApprove)
  const { data: settings } = useScopeSettingsApi(!!entry)

  const [description, setDescription] = useState('')
  const [reason, setReason] = useState('')
  const [tier, setTier] = useState<ScopeTier>('t1')
  const [expiry, setExpiry] = useState<DurationChoice>({ kind: 'keep' })
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!entry) return
    setDescription(entry.description ?? '')
    setReason(entry.reason ?? '')
    setTier((entry.max_tier as ScopeTier) || 't1')
    setExpiry({ kind: 'keep' })
    setError(null)
  }, [entry])

  if (!entry) return null

  // Intrusive (T2) entries follow the owner's limit; others the one-off one.
  // Only what the policy allows can be picked: a permanent entry raised to
  // T2 where T2 must expire gets the longest allowed expiry by default.
  const base = durationPolicy(tier, settings, { isRequest: false })
  const durPolicy: DurationPolicy =
    !entry.expires_at && base.permanent === 'allowed' ? { ...base, permanent: 'hidden' } : base
  const keepAllowed = !!entry.expires_at || base.permanent === 'allowed'
  const duration = resolveDuration(
    expiry.kind === 'keep' && !keepAllowed ? null : expiry,
    durPolicy
  )

  const change: UpdateScopeTargetInput = {
    description: description.trim(),
    reason: reason.trim(),
    ...(tier !== (entry.max_tier || 't1') ? { max_tier: tier } : {}),
    ...(duration.kind === 'days' ? { expires_in_days: duration.days } : {}),
    ...(duration.kind === 'permanent' && entry.expires_at ? { clear_expiry: true } : {}),
  }
  const widening = isWideningChange(entry, change)
  // Scan approval decides whether scope entries need approval (Strict
  // only, RFC-072 §6); t2 then always needs one.
  const entriesNeedApproval = settings?.approval_policy?.entries_need_approval ?? true
  const needsApprovals =
    (settings?.effective_widening_approvals ?? 0) > 0 || (tier === 't2' && entriesNeedApproval)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (widening && !canApprove) {
      setError(t('scope.error.WIDENING_NEEDS_APPROVER'))
      return
    }
    setSaving(true)
    setError(null)
    try {
      const updated = await updateScopeTarget(entry.id ?? '', change)
      await invalidateScopeCache()
      toast.success(
        updated?.status === 'pending'
          ? t('scope.edit.pendingAgain', '{pattern} is waiting for approval again', {
              pattern: updated.pattern ?? '',
            })
          : t('scope.edit.saved', 'Scope entry saved')
      )
      onOpenChange(false)
    } catch (err) {
      setError(
        scopeErrorMessage(t, err, t('scope.entry.errSave', 'Could not save the scope entry.'))
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('scope.edit.title', 'Edit scope entry')}</DialogTitle>
          <DialogDescription>
            <code className="break-all">{entry.pattern}</code>: {coversText(entry)}.{' '}
            {t(
              'scope.edit.desc',
              'Type and pattern cannot change; remove the entry and add a new one instead.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form id={formId} onSubmit={submit} className="space-y-4">
            {error && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor={`${formId}-tier`}>
                {t('scope.entry.tierLabel', 'Deepest probe allowed')}
              </Label>
              <Select
                value={tier}
                onValueChange={(v) => {
                  setTier(v as ScopeTier)
                  setError(null)
                }}
              >
                <SelectTrigger id={`${formId}-tier`} className="w-full sm:w-56">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {['t0', 't1', 't2'].map((k) => (
                    <SelectItem key={k} value={k}>
                      {t(`scope.tier.label.${k}`, TIER_LABEL[k])}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {t(`scope.tier.hint.${tier}`, TIER_HINT[tier])}{' '}
                {t('scope.entry.tierTools', 'Runs: {tools}.', {
                  tools: t(`scope.tier.tools.${tier}`, TIER_TOOLS[tier]),
                })}
              </p>
            </div>
            <ScopeDurationField
              policy={durPolicy}
              value={duration}
              keepHint={keepAllowed ? expiryText(entry.expires_at) : undefined}
              onChange={(c) => {
                setExpiry(c)
                setError(null)
              }}
            />
            <div className="space-y-2">
              <Label htmlFor={`${formId}-reason`}>{t('scope.entry.reason', 'Reason')}</Label>
              <Textarea
                id={`${formId}-reason`}
                rows={2}
                maxLength={1000}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${formId}-desc`}>{t('scope.edit.description', 'Description')}</Label>
              <Input
                id={`${formId}-desc`}
                maxLength={1000}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            {widening && (
              <p className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">
                {t('scope.edit.widens', 'This widens the entry.')}{' '}
                {canApprove
                  ? needsApprovals
                    ? t(
                        'scope.edit.widensPending',
                        'It goes back to pending and authorizes nothing until another approver approves it.'
                      )
                    : !entriesNeedApproval
                      ? t(
                          'scope.edit.widensNoApproval',
                          'Scope entries need no approval while scan approval is not Strict: it takes effect at once; every administrator is told. You may be asked to confirm your identity.'
                        )
                      : t(
                          'scope.edit.widensNow',
                          'It takes effect at once; every administrator is told. You may be asked to confirm your identity.'
                        )
                  : t('scope.edit.widensApprover', 'Only a scope approver can make this change.')}
              </p>
            )}
          </form>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button type="submit" form={formId} disabled={saving}>
            {saving && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('common.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
