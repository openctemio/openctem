'use client'

import type { ReactNode } from 'react'
import Link from '@/components/link'
import { EpssChip } from '@/components/ui/epss-chip'
import { KevBadge } from '@/components/ui/kev-badge'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { MetaLine } from '@/features/shared/components/text-layout'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { useTranslation } from '@/context/i18n-provider'
import { dateFnsLocaleFor } from '@/lib/format-date'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { approvalRequester } from '@/features/findings/lib/approvals'
import type { ApiApproval } from '@/features/findings/types'
import { acceptanceDays } from '../lib/queues'
import { ChangedSinceRequest } from '@/features/findings/components/changed-since-request'

/** English fallbacks; the key is myWork.kind.<requested_status>. */
const KIND_LABELS: Record<string, string> = {
  false_positive: 'False positive',
  accepted: 'Risk acceptance',
}

/**
 * One finding status request in a My Work queue (Awaiting my review,
 * Requested by me): what is asked and how severe it is, the finding, who
 * asked and why, what changed since, the facts an approver weighs, and the
 * row's actions. Every text from the request is shown as plain text.
 */
export function ApprovalRow({
  approval,
  currentUserId,
  actions,
  status,
  focused,
  onFocus,
  rowRef,
}: {
  approval: ApiApproval
  currentUserId?: string
  /** The row's buttons (Approve / Reject, or Remind / Cancel). */
  actions?: ReactNode
  /** A status note shown in the chips line (Requested by me). */
  status?: ReactNode
  focused?: boolean
  onFocus?: () => void
  rowRef?: (el: HTMLLIElement | null) => void
}) {
  const { t, locale } = useTranslation()
  const dateLocale = dateFnsLocaleFor(locale)
  const kind = t(
    `myWork.kind.${approval.requested_status}`,
    KIND_LABELS[approval.requested_status] ?? approval.requested_status
  )
  const days =
    approval.requested_status === 'accepted'
      ? acceptanceDays(approval.created_at, approval.expires_at)
      : null
  const requester = approvalRequester(approval, currentUserId)
  const requesterName =
    requester.kind === 'you'
      ? t('myWork.requester.you', 'you')
      : requester.kind === 'member'
        ? toDisplayText(requester.name, 120)
        : requester.kind === 'actor'
          ? t(`findings.approvals.actor.${requester.actor}`, requester.actor)
          : t('myWork.requester.former', 'a former member')
  const title =
    toDisplayText(approval.finding_title, 300) || t('myWork.untitled', 'Untitled finding')
  const reason = toDisplayText(approval.justification, 240)
  const facts = approval.finding
  const changed = approval.changed_since_request ?? []
  const required = approval.approvals_required ?? 0
  const collected = approval.approvals_collected ?? 0

  return (
    <li
      ref={rowRef}
      tabIndex={0}
      onFocus={onFocus}
      data-slot="approval-row"
      data-focused={focused ? 'true' : undefined}
      aria-label={`${kind}: ${title}`}
      className={cn(
        'grid min-w-0 gap-x-4 gap-y-2 px-4 py-3 outline-none hover:bg-muted/40 focus-visible:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset md:grid-cols-[11rem_minmax(0,1fr)_auto] md:items-center',
        focused && 'bg-muted/40'
      )}
    >
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 md:flex-col md:items-start">
        <span className="text-sm font-medium">{kind}</span>
        {days !== null && (
          <span className="text-meta text-muted-foreground">
            {t('myWork.kind.days', '{count} days', { count: days })}
          </span>
        )}
        {facts?.severity && <SeverityBadge severity={facts.severity} />}
      </div>

      <div className="min-w-0">
        <Link
          href={`/findings/${encodeURIComponent(approval.finding_id)}`}
          dir="auto"
          className="block truncate text-body font-medium [unicode-bidi:isolate] hover:underline"
          tabIndex={-1}
        >
          {title}
        </Link>
        <MetaLine
          className="mt-0.5"
          items={[
            <span key="by">
              {t('myWork.requestedBy', 'Requested by {name}', { name: requesterName })}
            </span>,
            <RelativeTime key="at" date={approval.created_at} />,
            reason ? (
              <q key="why" dir="auto" className="text-foreground [unicode-bidi:isolate]">
                {reason}
              </q>
            ) : null,
          ]}
        />
        <div className="mt-1.5 flex min-w-0 flex-wrap items-center gap-1.5">
          <ChangedSinceRequest changes={changed} />
          {facts?.kev && <KevBadge />}
          {facts && <EpssChip score={facts.epss} />}
          {facts?.asset_name && (
            <span className="inline-flex h-6 max-w-[16rem] items-center rounded-md border px-2 text-xs">
              <span className="text-muted-foreground">{t('myWork.chip.asset', 'Asset')}</span>
              <span className="ms-1 truncate font-medium" dir="auto">
                {toDisplayText(facts.asset_name, 200)}
              </span>
            </span>
          )}
          {required > 1 && (
            <span className="inline-flex h-6 items-center rounded-md border px-2 text-xs">
              {t('myWork.chip.signoffs', '{collected} of {required} approvals', {
                collected,
                required,
              })}
            </span>
          )}
          {approval.decide_by && (
            <span className="text-meta text-muted-foreground">
              {t('myWork.decideBy', 'Expires undecided')} <RelativeTime date={approval.decide_by} />
            </span>
          )}
          {status}
        </div>
      </div>

      {actions && <div className="flex flex-wrap items-center gap-2 md:justify-end">{actions}</div>}
    </li>
  )
}
