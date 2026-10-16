'use client'

import { formatDistanceToNow } from 'date-fns'
import { AlertTriangle, Check, Clock, Hash, Pencil, ShieldQuestion, Trash2, X } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { copyToClipboard } from '@/lib/clipboard'
import {
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  type DetailMenuItem,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  SUPPRESSION_STATUS_BADGE,
  SUPPRESSION_TYPE_BADGE,
  suppressionStatusLabel,
  suppressionTypeLabel,
  type SuppressionRule,
} from '../types'

interface SuppressionDetailSheetProps {
  rule: SuppressionRule | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onEdit?: (rule: SuppressionRule) => void
  onApprove?: (rule: SuppressionRule) => void
  onReject?: (rule: SuppressionRule) => void
  onDelete?: (rule: SuppressionRule) => void
  /** An approver confirms they reviewed a flagged rule (clears the flag). */
  onReviewed?: (rule: SuppressionRule) => void
}

function relative(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return formatDistanceToNow(d, { addSuffix: true })
}

function Criterion({ value }: { value?: string | null }) {
  const { t } = useTranslation()
  return value ? (
    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs break-all">{value}</code>
  ) : (
    <span className="text-muted-foreground">{t('exceptions.detail.any', 'Any')}</span>
  )
}

/**
 * A suppression rule, on the shared detail-drawer frame (sensor drawer
 * layout). A pending rule leads with Approve / Reject for approvers.
 */
export function SuppressionDetailSheet({
  rule,
  open,
  onOpenChange,
  onEdit,
  onApprove,
  onReject,
  onDelete,
  onReviewed,
}: SuppressionDetailSheetProps) {
  const { t } = useTranslation()
  const canApprove = useHasPermission(Permission.SuppressionsApprove)
  const canWrite = useHasPermission(Permission.SuppressionsWrite)
  const canDelete = useHasPermission(Permission.SuppressionsDelete)
  if (!rule) return null

  const isPending = rule.status === 'pending'
  const reviewing = isPending && canApprove

  const menu: DetailMenuItem[] = []
  if (reviewing && canWrite && onEdit) {
    menu.push({
      label: t('exceptions.detail.edit', 'Edit'),
      icon: Pencil,
      onSelect: () => onEdit(rule),
    })
  }
  menu.push({
    label: t('exceptions.detail.copyId', 'Copy ID'),
    icon: Hash,
    onSelect: () => {
      copyToClipboard(rule.id)
      toast.success(t('exceptions.detail.idCopied', 'Rule ID copied to clipboard'))
    },
  })
  if (canDelete && onDelete) {
    menu.push({
      label: t('exceptions.detail.delete', 'Delete rule'),
      icon: Trash2,
      destructive: true,
      separatorBefore: true,
      onSelect: () => onDelete(rule),
    })
  }

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      header={
        <DetailHeader
          title={rule.name}
          badges={
            <>
              <Badge
                variant="outline"
                className={cn('text-xs', SUPPRESSION_STATUS_BADGE[rule.status])}
              >
                {suppressionStatusLabel(rule.status, t)}
              </Badge>
              <Badge
                variant="outline"
                className={cn('text-xs', SUPPRESSION_TYPE_BADGE[rule.suppression_type])}
              >
                {suppressionTypeLabel(rule.suppression_type, t)}
              </Badge>
            </>
          }
          meta={[
            t('exceptions.detail.requestedAgo', 'Requested {when}', {
              when: relative(rule.requested_at),
            }),
            rule.expires_at
              ? t('exceptions.detail.expiresAgo', 'Expires {when}', {
                  when: relative(rule.expires_at),
                })
              : t('exceptions.detail.neverExpires', 'Never expires'),
          ]}
          actions={
            reviewing ? (
              <>
                <Button size="sm" onClick={() => onApprove?.(rule)}>
                  <Check className="h-4 w-4" />
                  {t('exceptions.detail.approve', 'Approve')}
                </Button>
                <Button size="sm" variant="outline" onClick={() => onReject?.(rule)}>
                  <X className="h-4 w-4" />
                  {t('exceptions.detail.reject', 'Reject')}
                </Button>
              </>
            ) : canWrite && onEdit ? (
              <Button size="sm" variant="outline" onClick={() => onEdit(rule)}>
                <Pencil className="h-4 w-4" />
                {t('exceptions.detail.edit', 'Edit')}
              </Button>
            ) : undefined
          }
          menu={menu}
          onClose={() => onOpenChange(false)}
        />
      }
    >
      <div className="space-y-5">
        {rule.review_flagged_at && (
          <DetailCallout
            tone="warning"
            icon={AlertTriangle}
            title={t('exceptions.detail.reviewTitle', 'Review this rule')}
            actions={
              canApprove && onReviewed ? (
                <Button size="sm" variant="outline" onClick={() => onReviewed(rule)}>
                  <Check className="h-4 w-4" />
                  {t('exceptions.detail.markReviewed', 'Mark as reviewed')}
                </Button>
              ) : undefined
            }
          >
            {t(
              'exceptions.detail.reviewBody',
              'This rule had no end date. It was given one ({when}). Check whether it should still suppress findings; to keep it after that date, submit a new rule.',
              { when: relative(rule.expires_at) }
            )}
          </DetailCallout>
        )}
        {isPending && !canApprove && (
          <DetailCallout
            tone="info"
            icon={Clock}
            title={t('exceptions.detail.waitingTitle', 'Waiting for approval')}
          >
            {t(
              'exceptions.detail.waitingBody',
              'The rule suppresses nothing until someone with the approve permission accepts it.'
            )}
          </DetailCallout>
        )}
        {rule.status === 'rejected' && rule.rejection_reason && (
          <DetailCallout
            tone="destructive"
            icon={X}
            title={t('exceptions.detail.rejectedTitle', 'Rejected')}
          >
            {rule.rejection_reason}
          </DetailCallout>
        )}

        <DetailSections>
          {rule.description && (
            <DetailSection title={t('exceptions.detail.description', 'Description')}>
              <p className="text-sm whitespace-pre-wrap text-muted-foreground">
                {rule.description}
              </p>
            </DetailSection>
          )}

          <DetailSection
            title={t('exceptions.detail.criteria', 'Matching criteria')}
            icon={ShieldQuestion}
          >
            <DetailFieldGrid>
              <DetailField label={t('exceptions.detail.tool', 'Tool')}>
                <Criterion value={rule.tool_name} />
              </DetailField>
              <DetailField label={t('exceptions.detail.ruleId', 'Rule ID')}>
                <Criterion value={rule.rule_id} />
              </DetailField>
              <DetailField label={t('exceptions.detail.pathPattern', 'Path pattern')} full>
                <Criterion value={rule.path_pattern} />
              </DetailField>
              <DetailField label={t('exceptions.detail.asset', 'Asset')} full>
                <Criterion value={rule.asset_id} />
              </DetailField>
            </DetailFieldGrid>
          </DetailSection>

          <DetailSection title={t('exceptions.detail.workflow', 'Approval workflow')} icon={Clock}>
            <DetailFieldGrid>
              <DetailField label={t('exceptions.detail.requested', 'Requested')}>
                {relative(rule.requested_at)}
              </DetailField>
              <DetailField label={t('exceptions.detail.requestedBy', 'Requested by')}>
                {/* A request no user made (a CI job) names its requester. */}
                <span className="font-mono">
                  {rule.requested_by_actor || rule.requested_by.slice(0, 8)}
                </span>
              </DetailField>
              {rule.approved_at && (
                <DetailField label={t('exceptions.detail.approved', 'Approved')}>
                  {relative(rule.approved_at)}
                </DetailField>
              )}
              {rule.rejected_at && (
                <DetailField label={t('exceptions.detail.rejected', 'Rejected')}>
                  {relative(rule.rejected_at)}
                </DetailField>
              )}
              <DetailField label={t('exceptions.detail.expires', 'Expires')}>
                {rule.expires_at
                  ? relative(rule.expires_at)
                  : t('exceptions.detail.never', 'Never')}
              </DetailField>
              <DetailField label={t('exceptions.detail.created', 'Created')}>
                {relative(rule.created_at)}
              </DetailField>
            </DetailFieldGrid>
          </DetailSection>
        </DetailSections>
      </div>
    </DetailSheet>
  )
}
