'use client'

import { formatDistanceToNow } from 'date-fns'
import { Check, Clock, Hash, Pencil, ShieldQuestion, Trash2, X } from 'lucide-react'
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
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  SUPPRESSION_STATUS_BADGE,
  SUPPRESSION_STATUS_LABELS,
  SUPPRESSION_TYPE_BADGE,
  SUPPRESSION_TYPE_LABELS,
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
}

function relative(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return formatDistanceToNow(d, { addSuffix: true })
}

function Criterion({ value }: { value?: string | null }) {
  return value ? (
    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs break-all">{value}</code>
  ) : (
    <span className="text-muted-foreground">Any</span>
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
}: SuppressionDetailSheetProps) {
  const canApprove = useHasPermission(Permission.SuppressionsApprove)
  const canWrite = useHasPermission(Permission.SuppressionsWrite)
  const canDelete = useHasPermission(Permission.SuppressionsDelete)
  if (!rule) return null

  const isPending = rule.status === 'pending'
  const reviewing = isPending && canApprove

  const menu: DetailMenuItem[] = []
  if (reviewing && canWrite && onEdit) {
    menu.push({ label: 'Edit', icon: Pencil, onSelect: () => onEdit(rule) })
  }
  menu.push({
    label: 'Copy ID',
    icon: Hash,
    onSelect: () => {
      copyToClipboard(rule.id)
      toast.success('Rule ID copied to clipboard')
    },
  })
  if (canDelete && onDelete) {
    menu.push({
      label: 'Delete rule',
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
                {SUPPRESSION_STATUS_LABELS[rule.status]}
              </Badge>
              <Badge
                variant="outline"
                className={cn('text-xs', SUPPRESSION_TYPE_BADGE[rule.suppression_type])}
              >
                {SUPPRESSION_TYPE_LABELS[rule.suppression_type]}
              </Badge>
            </>
          }
          meta={[
            `Requested ${relative(rule.requested_at)}`,
            rule.expires_at ? `Expires ${relative(rule.expires_at)}` : 'Never expires',
          ]}
          actions={
            reviewing ? (
              <>
                <Button size="sm" onClick={() => onApprove?.(rule)}>
                  <Check className="h-4 w-4" />
                  Approve
                </Button>
                <Button size="sm" variant="outline" onClick={() => onReject?.(rule)}>
                  <X className="h-4 w-4" />
                  Reject
                </Button>
              </>
            ) : canWrite && onEdit ? (
              <Button size="sm" variant="outline" onClick={() => onEdit(rule)}>
                <Pencil className="h-4 w-4" />
                Edit
              </Button>
            ) : undefined
          }
          menu={menu}
          onClose={() => onOpenChange(false)}
        />
      }
    >
      <div className="space-y-5">
        {isPending && !canApprove && (
          <DetailCallout tone="info" icon={Clock} title="Waiting for approval">
            The rule suppresses nothing until someone with the approve permission accepts it.
          </DetailCallout>
        )}
        {rule.status === 'rejected' && rule.rejection_reason && (
          <DetailCallout tone="destructive" icon={X} title="Rejected">
            {rule.rejection_reason}
          </DetailCallout>
        )}

        <DetailSections>
          {rule.description && (
            <DetailSection title="Description">
              <p className="text-sm whitespace-pre-wrap text-muted-foreground">
                {rule.description}
              </p>
            </DetailSection>
          )}

          <DetailSection title="Matching criteria" icon={ShieldQuestion}>
            <DetailFieldGrid>
              <DetailField label="Tool">
                <Criterion value={rule.tool_name} />
              </DetailField>
              <DetailField label="Rule ID">
                <Criterion value={rule.rule_id} />
              </DetailField>
              <DetailField label="Path pattern" full>
                <Criterion value={rule.path_pattern} />
              </DetailField>
              <DetailField label="Asset" full>
                <Criterion value={rule.asset_id} />
              </DetailField>
            </DetailFieldGrid>
          </DetailSection>

          <DetailSection title="Approval workflow" icon={Clock}>
            <DetailFieldGrid>
              <DetailField label="Requested">{relative(rule.requested_at)}</DetailField>
              <DetailField label="Requested by">
                <span className="font-mono">{rule.requested_by.slice(0, 8)}</span>
              </DetailField>
              {rule.approved_at && (
                <DetailField label="Approved">{relative(rule.approved_at)}</DetailField>
              )}
              {rule.rejected_at && (
                <DetailField label="Rejected">{relative(rule.rejected_at)}</DetailField>
              )}
              <DetailField label="Expires">
                {rule.expires_at ? relative(rule.expires_at) : 'Never'}
              </DetailField>
              <DetailField label="Created">{relative(rule.created_at)}</DetailField>
            </DetailFieldGrid>
          </DetailSection>
        </DetailSections>
      </div>
    </DetailSheet>
  )
}
