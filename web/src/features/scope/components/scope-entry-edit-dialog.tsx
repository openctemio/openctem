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
import { coversText, daysUntil, expiryText, TIER_HINT, TIER_LABEL } from '../lib/scope-entry'

type ExpiryChoice = 'keep' | 'days' | 'permanent'

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
  const maxDays = Math.max(1, settings?.one_off_max_days ?? 7)

  const [description, setDescription] = useState('')
  const [reason, setReason] = useState('')
  const [tier, setTier] = useState<ScopeTier>('t1')
  const [expiry, setExpiry] = useState<ExpiryChoice>('keep')
  const [days, setDays] = useState(7)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!entry) return
    setDescription(entry.description ?? '')
    setReason(entry.reason ?? '')
    setTier((entry.max_tier as ScopeTier) || 't1')
    setExpiry('keep')
    setDays(Math.min(7, maxDays))
    setError(null)
  }, [entry, maxDays])

  if (!entry) return null

  const change: UpdateScopeTargetInput = {
    description: description.trim(),
    reason: reason.trim(),
    ...(tier !== (entry.max_tier || 't1') ? { max_tier: tier } : {}),
    ...(expiry === 'days' ? { expires_in_days: Math.min(Math.max(1, days || 1), maxDays) } : {}),
    ...(expiry === 'permanent' ? { clear_expiry: true } : {}),
  }
  const widening = isWideningChange(entry, change)
  const needsApprovals = (settings?.effective_widening_approvals ?? 0) > 0 || tier === 't2'

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (widening && !canApprove) {
      setError(t('scope.error.WIDENING_NEEDS_APPROVER'))
      return
    }
    if (tier === 't2' && (expiry === 'permanent' || (!entry.expires_at && expiry === 'keep'))) {
      setError(t('scope.error.INTRUSIVE_NEEDS_EXPIRY'))
      return
    }
    setSaving(true)
    setError(null)
    try {
      const updated = await updateScopeTarget(entry.id ?? '', change)
      await invalidateScopeCache()
      toast.success(
        updated?.status === 'pending'
          ? `${updated.pattern} is waiting for approval again`
          : 'Scope entry saved'
      )
      onOpenChange(false)
    } catch (err) {
      setError(scopeErrorMessage(t, err, 'Could not save the scope entry.'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit scope entry</DialogTitle>
          <DialogDescription>
            <code className="break-all">{entry.pattern}</code>: {coversText(entry)}. Type and
            pattern cannot change; remove the entry and add a new one instead.
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
              <Label htmlFor={`${formId}-expiry`}>Expiry</Label>
              <Select value={expiry} onValueChange={(v) => setExpiry(v as ExpiryChoice)}>
                <SelectTrigger id={`${formId}-expiry`} className="w-full sm:w-64">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="keep">Keep ({expiryText(entry.expires_at)})</SelectItem>
                  <SelectItem value="days">Expire in a number of days</SelectItem>
                  {entry.expires_at && <SelectItem value="permanent">Make permanent</SelectItem>}
                </SelectContent>
              </Select>
              {expiry === 'days' && (
                <div className="flex items-center gap-2">
                  <Input
                    type="number"
                    min={1}
                    max={maxDays}
                    value={days}
                    onChange={(e) => setDays(Number(e.target.value))}
                    className="w-24"
                    aria-label="Days from now"
                  />
                  <span className="text-sm text-muted-foreground">
                    days from now (1 to {maxDays})
                  </span>
                </div>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${formId}-tier`}>Deepest probe allowed</Label>
              <Select value={tier} onValueChange={(v) => setTier(v as ScopeTier)}>
                <SelectTrigger id={`${formId}-tier`} className="w-full sm:w-56">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {['t0', 't1', 't2'].map((k) => (
                    <SelectItem key={k} value={k}>
                      {TIER_LABEL[k]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">{TIER_HINT[tier]}</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${formId}-reason`}>Reason</Label>
              <Textarea
                id={`${formId}-reason`}
                rows={2}
                maxLength={1000}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${formId}-desc`}>Description</Label>
              <Input
                id={`${formId}-desc`}
                maxLength={1000}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            {widening && (
              <p className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm">
                This widens the entry.{' '}
                {canApprove
                  ? needsApprovals
                    ? 'It goes back to pending and authorizes nothing until another approver approves it.'
                    : 'You may be asked to confirm your identity.'
                  : 'Only a scope approver can make this change.'}
              </p>
            )}
          </form>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Cancel
          </Button>
          <Button type="submit" form={formId} disabled={saving}>
            {saving && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
