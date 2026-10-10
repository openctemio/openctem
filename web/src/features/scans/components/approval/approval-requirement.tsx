'use client'

/**
 * What the organization's scan approval rules ask of a scan (RFC-073): the
 * rules that caught it, how many approvers, who, and the evidence. Used by
 * the New Scan review and the approvals inbox.
 */

import { ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import type { ScanApprovalEvaluation } from '@/lib/api/scan-approval-hooks'

type T = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** "2 approvers (admin)" style text for an evaluation. */
export function approversText(t: T, ev: ScanApprovalEvaluation): string {
  const n = ev.approvals ?? 1
  const who: string[] = []
  for (const r of ev.approver_roles ?? []) {
    who.push(
      r === 'owner'
        ? t('scans.approval.roleOwner', 'an owner')
        : t('scans.approval.roleAdmin', 'an administrator')
    )
  }
  if ((ev.approver_user_ids ?? []).length > 0) {
    who.push(
      t('scans.approval.namedPeople', '{count} named people', {
        count: (ev.approver_user_ids ?? []).length,
      })
    )
  }
  const base =
    n === 1
      ? t('scans.approval.oneApprover', '1 approver')
      : t('scans.approval.nApprovers', '{count} distinct approvers', { count: n })
  return who.length > 0
    ? t('scans.approval.approversBy', '{base}: {who}', { base, who: who.join(', ') })
    : t('scans.approval.approversAny', '{base} with the scan approval permission', { base })
}

export interface ApprovalRequirementProps {
  evaluation: ScanApprovalEvaluation
  justification: string
  ticket: string
  onJustification: (v: string) => void
  onTicket: (v: string) => void
}

/** The New Scan review's approval block. */
export function ApprovalRequirement({
  evaluation,
  justification,
  ticket,
  onJustification,
  onTicket,
}: ApprovalRequirementProps) {
  const { t } = useTranslation()
  if (!evaluation.required) return null
  return (
    <div
      className="space-y-3 rounded-md border border-warning/40 bg-warning/10 p-3"
      data-testid="approval-requirement"
    >
      <div className="flex items-start gap-2">
        <ShieldCheck className="mt-0.5 size-4 shrink-0" aria-hidden />
        <div className="space-y-1 text-sm">
          <p className="font-medium">
            {t('scans.approval.needsApprovalBy', 'Needs approval by {who}', {
              who: approversText(t, evaluation),
            })}
          </p>
          <p className="text-muted-foreground">
            {t(
              'scans.approval.savedAndSubmitted',
              'The scan is saved and submitted for approval. It runs once approved, or at its schedule.'
            )}
          </p>
          <div className="flex flex-wrap gap-1">
            {(evaluation.matched ?? []).map((r) => (
              <Badge key={r.id} variant="outline">
                {r.name}
              </Badge>
            ))}
          </div>
        </div>
      </div>
      {evaluation.require_justification && (
        <div className="space-y-1">
          <Label htmlFor="approval-justification">
            {t('scans.approval.justification', 'Justification')}
          </Label>
          <Textarea
            id="approval-justification"
            rows={2}
            maxLength={2000}
            value={justification}
            onChange={(e) => onJustification(e.target.value)}
          />
        </div>
      )}
      {evaluation.require_ticket && (
        <div className="space-y-1">
          <Label htmlFor="approval-ticket">{t('scans.approval.ticket', 'Change ticket')}</Label>
          <Input
            id="approval-ticket"
            maxLength={100}
            value={ticket}
            onChange={(e) => onTicket(e.target.value)}
          />
        </div>
      )}
    </div>
  )
}

/** What evidence is still missing ("" when none). */
export function missingEvidence(
  t: T,
  ev: ScanApprovalEvaluation | undefined,
  justification: string,
  ticket: string
): string {
  if (!ev?.required) return ''
  if (ev.require_justification && !justification.trim()) {
    return t('scans.approval.needJustification', 'Add a justification for the approvers.')
  }
  if (ev.require_ticket && !ticket.trim()) {
    return t('scans.approval.needTicket', 'Add the change ticket id.')
  }
  for (const p of ev.ticket_patterns ?? []) {
    try {
      if (!new RegExp(`^(?:${p})$`).test(ticket.trim())) {
        return t(
          'scans.approval.ticketFormat',
          'The change ticket id does not have the required format.'
        )
      }
    } catch {
      // The server checks the format; an expression the browser cannot read is left to it.
    }
  }
  return ''
}
