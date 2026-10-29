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
        if (!cancelled)
          setPreviewError(
            scopeErrorMessage(t, err, t('easmReview.rule.previewFailed', 'The preview failed.'))
          )
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
              ? t('easmReview.rule.summaryAccept', 'scope entry, covers {what}, permanent', {
                  what: coversText({ pattern: entry?.pattern ?? suggestion.pattern }),
                })
              : t(
                  'easmReview.rule.summaryReject',
                  'exclusion, names it covers are marked not ours'
                ),
          message: refusal ?? undefined,
          impact: refusal
            ? []
            : [
                accept
                  ? {
                      title: t('easmReview.rule.confirmedTitle', 'Confirmed as yours'),
                      names: confirm,
                    }
                  : { title: t('easmReview.rule.rejectedTitle', 'Marked not ours'), names: reject },
                ...(blocked.length > 0
                  ? [
                      {
                        title: t('easmReview.rule.stayOutTitle', 'Stay out'),
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
            ? t(
                changed === 1
                  ? 'easmReview.rule.toastActiveOne'
                  : 'easmReview.rule.toastActiveMany',
                changed === 1
                  ? '{pattern} is in scope; {n} name confirmed'
                  : '{pattern} is in scope; {n} names confirmed',
                { pattern: suggestion.pattern ?? '', n: changed }
              )
            : t('easmReview.rule.toastPending', '{pattern} is waiting for approval', {
                pattern: suggestion.pattern ?? '',
              }),
          res?.entry?.status === 'active'
            ? undefined
            : {
                description: t(
                  'easmReview.rule.toastPendingHint',
                  'The names it covers are confirmed once another approver approves it.'
                ),
              }
        )
      } else {
        toast.success(
          t(
            changed === 1
              ? 'easmReview.rule.toastRejectedOne'
              : 'easmReview.rule.toastRejectedMany',
            changed === 1 ? '{n} name marked not ours' : '{n} names marked not ours',
            { n: changed }
          ),
          {
            description: t(
              'easmReview.rule.toastRejectedHint',
              'The exclusion {pattern} waits for its approval; until then it does not stop scans.',
              { pattern: suggestion.pattern ?? '' }
            ),
          }
        )
      }
      onApplied()
      onOpenChange(false)
    } catch (err) {
      toast.error(
        scopeErrorMessage(t, err, t('easmReview.rule.applyFailed', 'The rule was not applied.'))
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {accept
              ? t('easmReview.rule.accept', 'Accept as rule')
              : t('easmReview.rule.reject', 'Reject as rule')}
          </DialogTitle>
          <DialogDescription>
            {accept ? (
              <>
                {t('easmReview.rule.acceptIntro1', 'Adds the scope entry')}{' '}
                <code className="break-all">{suggestion.pattern}</code>.{' '}
                {t(
                  'easmReview.rule.acceptIntro2',
                  'Names below it are confirmed as yours once it is in effect, now and when discovery finds more.'
                )}
              </>
            ) : (
              <>
                {t('easmReview.rule.rejectIntro1', 'Adds the exclusion')}{' '}
                <code className="break-all">{suggestion.pattern}</code>{' '}
                {t(
                  'easmReview.rule.rejectIntro2',
                  'and marks the names it covers as not yours. New names it matches are rejected on arrival.'
                )}
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
                <Loader2 className="h-4 w-4 animate-spin" />{' '}
                {t('easmReview.rule.working', 'Working out what changes…')}
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
                          // A request only when the server would not apply it
                          // at once (Strict scan approval).
                          isRequest: accept && !canApprove && entry?.status !== 'active',
                          stepUp: preview.step_up_required,
                        }
                  }
                />
              )
            )}

            <div className="space-y-2">
              <Label htmlFor={`${id}-reason`}>{t('easmReview.rule.reason', 'Reason')}</Label>
              <Textarea
                id={`${id}-reason`}
                rows={2}
                maxLength={1000}
                value={reason}
                placeholder={
                  accept
                    ? t(
                        'easmReview.rule.reasonPlaceholderAccept',
                        'Why is this yours? For example: our dev environment, ticket OPS-12.'
                      )
                    : t(
                        'easmReview.rule.reasonPlaceholderReject',
                        'Why is this not yours? For example: a reseller domain.'
                      )
                }
                onChange={(e) => setReason(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                {t('easmReview.rule.reasonHint', 'Required. Kept in the audit log.')}
              </p>
            </div>
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            {t('easmReview.rule.cancel', 'Cancel')}
          </Button>
          <Button
            variant={accept ? 'default' : 'destructive'}
            onClick={() => void submit()}
            disabled={saving || !reason.trim() || !!refusal || !preview}
          >
            {saving && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {accept
              ? t('easmReview.rule.accept', 'Accept as rule')
              : t('easmReview.rule.reject', 'Reject as rule')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
