'use client'

/**
 * One exploration step in a drawer (api docs/architecture/exploration.md):
 * the question, why it was asked (the rationale is free text from a rule, a
 * person or an AI, rendered as text only), what it came from and what it
 * produced, its answers (a heuristic or AI answer is labelled as such, never
 * as proof), the inputs of its score and, when blocked, why. Approve and
 * Dismiss show only with scans:approve; the API checks again.
 */

import { Check, X } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import {
  DetailCallout,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  ErrorState,
  KeyValueList,
  RelativeTime,
  TonePill,
  type KeyValueItem,
} from '@/features/shared'
import { Can, Permission } from '@/lib/permissions'
import { useLead } from '../hooks/use-leads'
import {
  blockedReasonLabel,
  canApproveLead,
  canDismissLead,
  effectLabel,
  groupLinks,
  leadQuestion,
  leadTitle,
  linkEndLabel,
  linkHref,
  linkRelLabel,
  originLabel,
  reasonLabel,
  stateLabel,
  stateTone,
  tierLabel,
  verdictLabel,
  verdictTierLabel,
  type LeadLink,
} from '../lib/leads'

export interface LeadDetailSheetProps {
  leadId: string | null
  onOpenChange: (open: boolean) => void
  /** Opens another lead in place (a `lead` link). */
  onOpenLead: (id: string) => void
  onApprove: (ids: string[]) => void
  onDismiss: (ids: string[]) => void
  /** Subject display name, when the page already resolved it. */
  subjectName?: (id: string | undefined) => string
}

function LinkEnd({ link, onOpenLead }: { link: LeadLink; onOpenLead: (id: string) => void }) {
  const { t } = useTranslation()
  const label = linkEndLabel(t, link.end_kind)
  const href = linkHref(link)
  const id = link.end_id ? link.end_id.slice(0, 8) : ''
  if (href) {
    return (
      <Link href={href} className="text-primary hover:underline">
        {label} <span className="font-mono">{id}</span>
      </Link>
    )
  }
  if (link.end_kind === 'lead' && link.end_id) {
    const leadId = link.end_id
    return (
      <button
        type="button"
        className="text-primary hover:underline"
        onClick={() => onOpenLead(leadId)}
      >
        {label} <span className="font-mono">{id}</span>
      </button>
    )
  }
  return (
    <span>
      {label} {id && <span className="font-mono">{id}</span>}
    </span>
  )
}

export function LeadDetailSheet({
  leadId,
  onOpenChange,
  onOpenLead,
  onApprove,
  onDismiss,
  subjectName,
}: LeadDetailSheetProps) {
  const { t } = useTranslation()
  const { lead, error, isLoading } = useLead(leadId)
  const close = () => onOpenChange(false)

  const inputs = lead?.score_inputs ?? {}
  const scoreItems: KeyValueItem[] = lead
    ? [
        {
          key: 'score',
          label: t('exploration.score.score', 'Score'),
          value: lead.score.toFixed(3),
        },
        ...(inputs.p_useful !== undefined
          ? [
              {
                key: 'p',
                label: t('exploration.score.pUseful', 'Chance it is useful'),
                value: `${Math.round(inputs.p_useful * 100)}%`,
              },
            ]
          : []),
        ...(inputs.value !== undefined
          ? [
              {
                key: 'v',
                label: t('exploration.score.value', 'Value'),
                value: String(inputs.value),
              },
            ]
          : []),
        ...(inputs.cost_seconds !== undefined
          ? [
              {
                key: 'c',
                label: t('exploration.score.cost', 'Expected time'),
                value: t('exploration.score.seconds', '{count} s', {
                  count: Math.round(inputs.cost_seconds),
                }),
              },
            ]
          : []),
        ...(inputs.tried !== undefined
          ? [
              {
                key: 'h',
                label: t('exploration.score.history', 'Past answers of this kind'),
                value: t('exploration.score.historyValue', '{useful} useful of {tried}', {
                  useful: inputs.useful ?? 0,
                  tried: inputs.tried,
                }),
              },
            ]
          : []),
        ...(inputs.demoted
          ? [
              {
                key: 'd',
                label: t('exploration.score.demoted', 'Demoted'),
                value: t(
                  'exploration.score.demotedValue',
                  'Its last answers were not useful, so it ranks lower'
                ),
              },
            ]
          : []),
      ]
    : []

  return (
    <DetailSheet
      open={!!leadId}
      onOpenChange={onOpenChange}
      header={
        <DetailHeader
          title={lead ? leadQuestion(t, lead.type) : t('exploration.sheet.loading', 'Next step')}
          badges={
            lead ? (
              <TonePill tone={stateTone(lead.state)} label={stateLabel(t, lead.state)} />
            ) : undefined
          }
          meta={
            lead
              ? [
                  leadTitle(t, lead.type),
                  tierLabel(t, lead.tier),
                  t('exploration.sheet.openedBy', 'Opened by {origin}', {
                    origin: originLabel(t, lead.origin).toLowerCase(),
                  }),
                ]
              : undefined
          }
          actions={
            lead && (canApproveLead(lead) || canDismissLead(lead)) ? (
              <Can permission={Permission.ScansApprove}>
                <div className="flex flex-wrap gap-2">
                  {canApproveLead(lead) && (
                    <Button size="sm" onClick={() => onApprove([lead.id])}>
                      <Check className="me-1.5 h-4 w-4" aria-hidden />
                      {t('exploration.actions.approve', 'Approve')}
                    </Button>
                  )}
                  <Button size="sm" variant="outline" onClick={() => onDismiss([lead.id])}>
                    <X className="me-1.5 h-4 w-4" aria-hidden />
                    {t('exploration.actions.dismiss', 'Dismiss')}
                  </Button>
                </div>
              </Can>
            ) : undefined
          }
          onClose={close}
        />
      }
    >
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-5 w-2/3" />
          <Skeleton className="h-5 w-1/2" />
        </div>
      ) : error ? (
        <ErrorState title={t('exploration.sheet.errorTitle', 'this step')} error={error} />
      ) : lead ? (
        <DetailSections>
          {lead.state === 'blocked' && lead.blocked_reason && (
            <DetailCallout tone="warning" title={t('exploration.sheet.blocked', 'Blocked')}>
              {blockedReasonLabel(t, lead.blocked_reason)}
            </DetailCallout>
          )}
          <DetailSection title={t('exploration.sheet.why', 'Why')}>
            <KeyValueList
              items={[
                {
                  key: 'subject',
                  label: t('exploration.sheet.subject', 'Asset'),
                  value: lead.subject_asset_id ? (
                    <Link
                      href={`/assets/${encodeURIComponent(lead.subject_asset_id)}`}
                      className="text-primary hover:underline"
                    >
                      {subjectName
                        ? subjectName(lead.subject_asset_id)
                        : lead.subject_asset_id.slice(0, 8)}
                    </Link>
                  ) : (
                    t('exploration.sheet.noSubject', 'None')
                  ),
                },
                {
                  key: 'reason',
                  label: t('exploration.sheet.reason', 'Because'),
                  value: reasonLabel(t, lead.reason_code),
                },
                {
                  key: 'opened',
                  label: t('exploration.sheet.opened', 'Opened'),
                  value: <RelativeTime date={lead.created_at} />,
                },
                {
                  key: 'attempts',
                  label: t('exploration.sheet.attempts', 'Attempts'),
                  value: String(lead.attempts),
                },
                ...(lead.approved_at
                  ? [
                      {
                        key: 'approved',
                        label: t('exploration.sheet.approved', 'Approved'),
                        value: <RelativeTime date={lead.approved_at} />,
                      },
                    ]
                  : []),
              ]}
            />
            {lead.rationale && (
              // Text only: React escapes it, nothing is parsed as HTML or markdown.
              <p className="whitespace-pre-wrap break-words text-sm text-muted-foreground">
                {lead.rationale}
              </p>
            )}
          </DetailSection>

          {groupLinks(lead.links).map(([rel, links]) => (
            <DetailSection key={rel} title={linkRelLabel(t, rel)} count={links.length}>
              <ul className="space-y-1 text-sm">
                {links.map((l, i) => (
                  <li key={`${l.end_kind}-${l.end_id ?? i}`} className="flex flex-wrap gap-x-3">
                    <LinkEnd link={l} onOpenLead={onOpenLead} />
                    {l.effect && (
                      <span className="text-muted-foreground">{effectLabel(t, l.effect)}</span>
                    )}
                    {l.outcome_reason && (
                      <span className="break-words text-muted-foreground">{l.outcome_reason}</span>
                    )}
                  </li>
                ))}
              </ul>
            </DetailSection>
          ))}

          {(lead.verdicts?.length ?? 0) > 0 && (
            <DetailSection
              title={t('exploration.sheet.answers', 'Answers')}
              count={lead.verdicts?.length}
            >
              <ul className="space-y-3 text-sm">
                {lead.verdicts?.map((v, i) => (
                  <li key={`${v.created_at}-${i}`} className="space-y-0.5">
                    <div className="flex flex-wrap items-baseline gap-x-3">
                      <span className="font-medium">{verdictLabel(t, v.verdict)}</span>
                      <span className="text-meta text-muted-foreground">
                        {verdictTierLabel(t, v.tier)}
                      </span>
                      <RelativeTime date={v.created_at} className="text-meta" />
                    </div>
                    {v.reason && (
                      <p className="whitespace-pre-wrap break-words text-muted-foreground">
                        {v.reason}
                      </p>
                    )}
                    {(v.evidence?.length ?? 0) > 0 && (
                      <p className="text-meta text-muted-foreground">
                        {t(
                          'exploration.sheet.evidence',
                          '{count, plural, one {# piece of evidence} other {# pieces of evidence}}',
                          { count: v.evidence?.length ?? 0 }
                        )}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </DetailSection>
          )}

          <DetailSection title={t('exploration.sheet.score', 'Why it ranks here')}>
            <KeyValueList items={scoreItems} />
          </DetailSection>
        </DetailSections>
      ) : null}
    </DetailSheet>
  )
}
