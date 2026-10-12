'use client'

/**
 * Accept or reject a suggested rule (RFC-054 §6.7), after a preview of
 * exactly what it changes.
 *
 * - Accept as rule: a permanent scope entry for the pattern, created like any
 *   other (step-up, the organization's approvals, audit, every admin
 *   notified). Once it is in effect the names it covers are confirmed.
 * - Reject as rule: a scope exclusion (it waits for its own approval) and the
 *   names it covers now are marked not ours; future names it matches are
 *   rejected on arrival.
 *
 * The preview (POST .../rules/preview) changes nothing; the dialog shows the
 * entry it would create and its status, the names confirmed or rejected, the
 * names that stay blocked and why, and any refusal, before the click.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
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
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  coversText,
  ScopeChangePreview,
  scopeErrorMessage,
  scopeErrorText,
  scopeRefusalLabel,
  type ScopeChangeLine,
} from '@/features/scope'
import {
  applyRule,
  previewRule,
  type EASMRuleAction,
  type EASMRulePreview,
  type EASMRuleSuggestion,
} from '../hooks/use-easm-rules'

interface EASMRuleDialogProps {
  suggestion: EASMRuleSuggestion | null
  action: Extract<EASMRuleAction, 'accept_rule' | 'reject_rule'>
  onOpenChange: (open: boolean) => void
  onApplied: () => void
}

export function EASMRuleDialog({
  suggestion,
  action,
  onOpenChange,
  onApplied,
}: EASMRuleDialogProps) {
  const { t } = useTranslation()
  const id = useId()
  const canApprove = useHasPermission(Permission.ScopeApprove)
  const [reason, setReason] = useState('')
  const [preview, setPreview] = useState<EASMRulePreview | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const debouncedReason = useDebounce(reason, 400)

  const open = suggestion !== null
  const accept = action === 'accept_rule'

  useEffect(() => {
    if (open) {
      setReason('')
      setPreview(null)
      setPreviewError(null)
    }
  }, [open, suggestion?.id, action])

  // The preview changes nothing; re-run it when the reason settles (the
  // server checks it is present).
  useEffect(() => {
    if (!suggestion) return
    let cancelled = false
    setLoading(true)
    previewRule({
      action,
      target_type: suggestion.target_type,
      pattern: suggestion.pattern,
      reason: debouncedReason.trim() || 'preview',
    })
      .then((p) => {
        if (!cancelled) {
          setPreview(p ?? null)
          setPreviewError(null)
        }
      })
      .catch((err) => {
        if (!cancelled) setPreviewError(scopeErrorMessage(t, err, 'The preview failed.'))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [suggestion, action, debouncedReason, t])

  if (!suggestion) return null

  const refusal = preview?.refusal?.code
    ? (scopeErrorText(t, preview.refusal.code) ?? preview.refusal.message)
    : null
  const entry = preview?.entry
  const confirm = (preview?.would_confirm ?? []).map((a) => a.name ?? '').filter(Boolean)
  const reject = (preview?.would_reject ?? []).map((a) => a.name ?? '').filter(Boolean)
  const blocked = preview?.stays_blocked ?? []
  const lines: ScopeChangeLine[] = preview
    ? [
        {
          key: 'rule',
          mark: refusal ? 'refused' : 'add',
          pattern: entry?.pattern ?? suggestion.pattern ?? '',
          summary: refusal
            ? undefined
            : accept
              ? `scope entry · covers ${coversText({ pattern: entry?.pattern ?? suggestion.pattern })} · permanent`
              : 'exclusion · names it covers are marked not ours',
          message: refusal ?? undefined,
          impact: refusal
            ? []
            : [
                accept
                  ? { title: 'Confirmed as yours', names: confirm }
                  : { title: 'Marked not ours', names: reject },
                ...(blocked.length > 0
                  ? [
                      {
                        title: 'Stay out',
                        names: blocked.map((b) => b.name ?? ''),
                        notes: Object.fromEntries(
                          blocked.map((b) => [b.name ?? '', scopeRefusalLabel(t, b.code)])
                        ),
                      },
                    ]
                  : []),
              ],
        },
      ]
    : []

  const submit = async () => {
    if (!reason.trim()) return
    setSaving(true)
    try {
      const res = await applyRule({
        action,
        target_type: suggestion.target_type,
        pattern: suggestion.pattern,
        reason: reason.trim(),
      })
      const changed = (res?.confirmed?.length ?? 0) + (res?.rejected?.length ?? 0)
      if (accept) {
        toast.success(
          res?.entry?.status === 'active'
            ? `${suggestion.pattern} is in scope; ${changed} ${changed === 1 ? 'name' : 'names'} confirmed`
            : `${suggestion.pattern} is waiting for approval`,
          res?.entry?.status === 'active'
            ? undefined
            : {
                description: 'The names it covers are confirmed once another approver approves it.',
              }
        )
      } else {
        toast.success(`${changed} ${changed === 1 ? 'name' : 'names'} marked not ours`, {
          description: `The exclusion ${suggestion.pattern} waits for its approval; until then it does not stop scans.`,
        })
      }
      onApplied()
      onOpenChange(false)
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, 'The rule was not applied.'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{accept ? 'Accept as rule' : 'Reject as rule'}</DialogTitle>
          <DialogDescription>
            {accept ? (
              <>
                Adds the scope entry <code className="break-all">{suggestion.pattern}</code>. Names
                below it are confirmed as yours once it is in effect, now and when discovery finds
                more.
              </>
            ) : (
              <>
                Adds the exclusion <code className="break-all">{suggestion.pattern}</code> and marks
                the names it covers as not yours. New names it matches are rejected on arrival.
              </>
            )}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4" aria-busy={loading}>
            {previewError && (
              <p role="alert" className="text-sm text-destructive">
                {previewError}
              </p>
            )}
            {loading && !preview ? (
              <p className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" /> Working out what changes…
              </p>
            ) : (
              preview && (
                <ScopeChangePreview
                  lines={lines}
                  loading={loading}
                  consequence={
                    refusal
                      ? undefined
                      : {
                          approvalsRequired:
                            entry?.status === 'active' ? 0 : (entry?.approvals_required ?? 0),
                          isRequest: accept && !canApprove,
                          stepUp: preview.step_up_required,
                        }
                  }
                />
              )
            )}

            <div className="space-y-2">
              <Label htmlFor={`${id}-reason`}>Reason</Label>
              <Textarea
                id={`${id}-reason`}
                rows={2}
                maxLength={1000}
                value={reason}
                placeholder={
                  accept
                    ? 'Why is this yours? For example: our dev environment, ticket OPS-12.'
                    : 'Why is this not yours? For example: a reseller domain.'
                }
                onChange={(e) => setReason(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">Required. Kept in the audit log.</p>
            </div>
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Cancel
          </Button>
          <Button
            variant={accept ? 'default' : 'destructive'}
            onClick={() => void submit()}
            disabled={saving || !reason.trim() || !!refusal || !preview}
          >
            {saving && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {accept ? 'Accept as rule' : 'Reject as rule'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
