'use client'

import { ExternalLink } from 'lucide-react'

import Link from '@/components/link'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { useFindingApi } from '@/features/findings/api/use-findings-api'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { toDisplayBlock, toDisplayText } from '@/lib/untrusted-text'

/**
 * What an approver decides on: the finding behind a request, shown inside the
 * approve and reject dialogs so a four-eyes decision is never made blind.
 *
 * The title, asset name and justification are untrusted (scanner or member
 * input): they render as plain text, capped, with bidi isolation, so a
 * right-to-left override cannot make a justification read differently.
 */
export function ApprovalFindingSummary({
  findingId,
  findingTitle,
  justification,
}: {
  findingId: string
  findingTitle?: string
  justification?: string
}) {
  const { t } = useTranslation()
  // One read of the finding the dialog is about (the list row carries only
  // the title). The API applies the caller's data scope to it.
  const { data: finding, isLoading } = useFindingApi(findingId)
  const title = toDisplayText(finding?.title ?? findingTitle ?? '', 300).trim()
  const assetName = finding?.asset?.name ? toDisplayText(finding.asset.name, 200) : ''
  const reason = justification ? toDisplayBlock(justification, 4000) : ''

  return (
    <div className="grid gap-2" data-testid="approval-finding-summary">
      <p dir="auto" className="text-sm font-medium [unicode-bidi:isolate] break-words">
        {title || t('findings.approvalLink.untitled', 'Untitled finding')}
      </p>
      {isLoading && !finding ? (
        <Skeleton className="h-5 w-48" />
      ) : finding ? (
        <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
          {finding.priority_class && (
            <PriorityClassBadge priorityClass={finding.priority_class} showTooltip={false} />
          )}
          <SeverityBadge severity={finding.severity} />
          {finding.cve_id && <span className="font-mono">{finding.cve_id}</span>}
          {assetName && (
            <span dir="auto" className="min-w-0 truncate [unicode-bidi:isolate]">
              {assetName}
            </span>
          )}
        </div>
      ) : null}
      {reason && (
        <div className="grid gap-1">
          <p className="text-xs font-medium text-muted-foreground">
            {t('findings.approvals.justificationLabel', 'Justification')}
          </p>
          <p
            dir="auto"
            className="max-h-40 overflow-y-auto whitespace-pre-wrap break-words text-sm [unicode-bidi:isolate]"
            data-testid="approval-justification"
          >
            {reason}
          </p>
        </div>
      )}
      <Link
        href={`/findings/${encodeURIComponent(findingId)}`}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex w-fit items-center gap-1 text-xs text-primary hover:underline"
      >
        {t('findings.approvals.openFinding', 'Open finding in a new tab')}
        <ExternalLink className="h-3 w-3" aria-hidden />
      </Link>
    </div>
  )
}
