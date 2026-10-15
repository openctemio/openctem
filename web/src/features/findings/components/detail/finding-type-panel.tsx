'use client'

/**
 * The evidence band of the drawer, by finding type, built from the finding
 * response (plus the evidence items for web findings):
 *
 *   SAST    the data flow from source to sink, and the code at the commit
 *   secret  the masked value, its kind and whether it was verified — never
 *           the value itself (revealing stays on the full page, audited)
 *   web     the scanner's HTTP evidence (request / response, masked)
 *
 * Other types have no extra band: their facts are in Fix and Intelligence.
 */

import { ExternalLink, KeyRound, Network, Route } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { safeHref } from '@/lib/safe-href'
import { Badge } from '@/components/ui/badge'
import {
  DetailField,
  DetailFieldGrid,
  DetailSection,
} from '@/features/shared/components/detail-sheet'
import { cn } from '@/lib/utils'
import { useFindingEvidenceItems } from '../../api/use-finding-evidence-items'
import { DATA_FLOW_LOCATION_CONFIG, type FindingDetail } from '../../types'
import { buildRepositoryCodeUrl } from '../../lib/repository-url'
import { FindingEvidenceItems } from './finding-evidence-items'

/** Steps shown in the drawer; the page's Data flow tab has the rest. */
export const TRACE_STEPS_SHOWN = 6

const WEB_SOURCES = new Set(['dast', 'easm'])

function TracePanel({
  finding,
  onOpenTrace,
}: {
  finding: FindingDetail
  onOpenTrace?: () => void
}) {
  const { t } = useTranslation()
  const steps = [...(finding.dataFlow?.steps ?? [])].sort((a, b) => (a.index ?? 0) - (b.index ?? 0))
  if (steps.length === 0) return null
  const shown = steps.slice(0, TRACE_STEPS_SHOWN)
  const codeUrl = buildRepositoryCodeUrl({
    repositoryUrl: finding.repositoryUrl,
    filePath: finding.filePath,
    startLine: finding.startLine,
    endLine: finding.endLine,
    commitSha: finding.dataFlow?.commitSha,
  })
  return (
    <DetailSection
      title={t('findings.typePanel.dataFlow', 'Data flow')}
      icon={Route}
      count={steps.length}
      actions={
        codeUrl ? (
          <a
            href={safeHref(codeUrl)}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="inline-flex items-center gap-1 text-xs underline-offset-2 hover:underline"
          >
            {t('findings.typePanel.openCode', 'Open the code')}
            <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        ) : undefined
      }
    >
      <ol className="space-y-2" aria-label={t('findings.typePanel.dataFlow', 'Data flow')}>
        {shown.map((s, i) => {
          const cfg = DATA_FLOW_LOCATION_CONFIG[s.type] ?? DATA_FLOW_LOCATION_CONFIG.intermediate
          return (
            <li key={`${s.index ?? i}-${s.path}-${s.line}`} className="flex min-w-0 gap-2">
              <span
                aria-hidden
                className={cn(
                  'mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold',
                  cfg.bgColor,
                  cfg.color
                )}
              >
                {i + 1}
              </span>
              <div className="min-w-0 flex-1">
                <p className="flex flex-wrap items-center gap-x-1.5 text-xs text-muted-foreground">
                  <span className={cn('font-medium', cfg.color)}>{t(cfg.labelKey, s.type)}</span>
                  {s.path && (
                    <span className="font-mono">
                      {s.path}
                      {s.line ? `:${s.line}` : ''}
                    </span>
                  )}
                </p>
                {(s.content || s.label) && (
                  <code
                    className="mt-0.5 block truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                    title={s.content || s.label}
                  >
                    {s.content || s.label}
                  </code>
                )}
              </div>
            </li>
          )
        })}
      </ol>
      {steps.length > shown.length && onOpenTrace && (
        <button
          type="button"
          onClick={onOpenTrace}
          className="rounded-sm text-xs font-medium text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          {t('findings.typePanel.moreSteps', '{count} more steps on the full page', {
            count: steps.length - shown.length,
          })}
        </button>
      )}
    </DetailSection>
  )
}

function SecretPanel({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation()
  const s = finding.secretDetails
  if (!s && finding.source !== 'secret') return null
  const validity =
    s?.revoked === true
      ? { text: t('findings.typePanel.revoked', 'Revoked'), tone: 'success' as const }
      : s?.valid === true
        ? {
            text: t('findings.typePanel.valid', 'Valid: still works'),
            tone: 'destructive' as const,
          }
        : s?.valid === false
          ? { text: t('findings.typePanel.invalid', 'Not valid'), tone: 'muted' as const }
          : {
              text: t('findings.typePanel.notVerified', 'Not verified by the scanner'),
              tone: 'muted' as const,
            }
  return (
    <DetailSection title={t('findings.typePanel.secret', 'Secret')} icon={KeyRound}>
      <DetailFieldGrid>
        <DetailField label={t('findings.typePanel.masked', 'Masked value')}>
          {s?.maskedValue ? <code className="font-mono text-xs">{s.maskedValue}</code> : null}
        </DetailField>
        <DetailField label={t('findings.typePanel.kind', 'Kind')}>
          {[s?.service, s?.secretType?.replace(/_/g, ' ')].filter(Boolean).join(' · ') || null}
        </DetailField>
        <DetailField label={t('findings.typePanel.validity', 'Validity')}>
          <Badge
            variant="outline"
            className={cn(
              validity.tone === 'destructive' && 'border-destructive/50 text-destructive',
              validity.tone === 'success' && 'border-success/50 text-success'
            )}
          >
            {validity.text}
          </Badge>
        </DetailField>
        <DetailField label={t('findings.typePanel.location', 'Location')}>
          {finding.filePath ? (
            <span className="font-mono text-xs">
              {finding.filePath}
              {finding.startLine ? `:${finding.startLine}` : ''}
            </span>
          ) : null}
        </DetailField>
        {s?.inHistoryOnly && (
          <DetailField label={t('findings.typePanel.history', 'History')} full>
            {t(
              'findings.typePanel.historyOnly',
              'Only in the repository history, not in the current files'
            )}
          </DetailField>
        )}
      </DetailFieldGrid>
    </DetailSection>
  )
}

function WebEvidencePanel({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation()
  const { data } = useFindingEvidenceItems(finding.id)
  const items = data?.data ?? []
  if (items.length === 0) return null
  return (
    <DetailSection
      title={t('findings.typePanel.httpEvidence', 'HTTP evidence')}
      icon={Network}
      count={items.length}
    >
      <FindingEvidenceItems findingId={finding.id} items={items.slice(0, 1)} />
    </DetailSection>
  )
}

export interface FindingTypePanelProps {
  finding: FindingDetail
  /** Opens the full page on the data-flow tab. */
  onOpenTrace?: () => void
}

export function FindingTypePanel({ finding, onOpenTrace }: FindingTypePanelProps) {
  if (finding.source === 'secret' || finding.findingType === 'secret') {
    return <SecretPanel finding={finding} />
  }
  if (finding.dataFlow?.steps?.length) {
    return <TracePanel finding={finding} onOpenTrace={onOpenTrace} />
  }
  if (WEB_SOURCES.has(finding.source)) {
    return <WebEvidencePanel finding={finding} />
  }
  return null
}
