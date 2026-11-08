'use client'

/**
 * The finding page's "Reported by N sources" section: what each source that
 * reported this finding said, kept per source so a later source never
 * overwrites an earlier one (docs/architecture/finding-source-records.md).
 *
 *   Where sources disagree   the fields with different values (severity,
 *                            vendor severity, CVSS, source check id, family,
 *                            status, fix type, title), one column per source
 *   Each source              its own title, text, ratings, native identity,
 *                            scores, ids and unmapped fields, folded
 *
 * Read: GET /api/v1/findings/{id}/source-records. Shown only when two or more
 * sources reported the finding (with one, the finding's own fields are that
 * source's values). A 404 (outside the caller's data scope) hides the
 * section. Every value is producer-supplied: rendered as text, free text
 * through UntrustedTextBlock.
 */

import { Layers } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Tag } from '@/components/ui/tag'
import { SeverityBadge } from '@/components/ui/severity-badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import {
  DetailDisclosure,
  DetailField,
  DetailFieldGrid,
  DetailSection,
} from '@/features/shared/components/detail-sheet'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { useSettleSignal } from '@/features/shared/components/settle-group'
import { KeyValueList } from '@/features/shared/components/text-layout'
import { UntrustedTextBlock } from '@/features/shared/components/untrusted-text-block'
import {
  useFindingSources,
  type FindingSourceDifference,
  type FindingSourceRecord,
} from '../../api/sources-api'
import { sightingChannelLabel } from './finding-seen-by'
import { ScoreRow } from './source-data-section'
import { SectionLoadError, isLoadFailure } from './section-load-error'

type T = ReturnType<typeof useTranslation>['t']

/** The label of a compared field. */
export function sourceFieldLabel(t: T, field: string): string {
  switch (field) {
    case 'severity':
      return t('findings.sources.field.severity', 'Severity')
    case 'vendor_severity':
      return t('findings.sources.field.vendorSeverity', 'Vendor severity')
    case 'cvss_score':
      return t('findings.sources.field.cvssScore', 'CVSS score')
    case 'native_id':
      return t('findings.sources.field.nativeId', 'Source check id')
    case 'family':
      return t('findings.sources.field.family', 'Family')
    case 'status':
      return t('findings.sources.field.status', 'Source status')
    case 'solution_type':
      return t('findings.sources.field.solutionType', 'Fix type')
    case 'title':
      return t('findings.sources.field.title', 'Title')
    default:
      return field.replace(/_/g, ' ')
  }
}

/** A short name of a source: its tool, else its sender, else its channel. */
export function sourceName(t: T, s: FindingSourceRecord): string {
  if (s.tool) return s.tool
  if (s.sensor?.name) return s.sensor.name
  if (s.sender && s.sender !== 'platform') return s.sender
  return sightingChannelLabel(t, s.channel)
}

/** How the source reached the platform: channel, and the sensor or sender. */
function sourceVia(t: T, s: FindingSourceRecord): string {
  const channel = sightingChannelLabel(t, s.channel)
  if (s.sensor?.name) return `${channel}, ${s.sensor.name}`
  if (s.sender === 'platform')
    return `${channel}, ${t('findings.seenBy.sharedSensor', 'Platform sensor')}`
  if (s.sender) return `${channel}, ${s.sender}`
  return channel
}

function DiffValue({ field, value }: { field: string; value: string }) {
  if (!value) return <span className="text-muted-foreground">-</span>
  if (field === 'severity') return <SeverityBadge severity={value} />
  if (field === 'native_id' || field === 'cvss_score') {
    return <span className="font-mono tabular-nums break-all">{value}</span>
  }
  return <span className="break-words">{value}</span>
}

function DifferencesTable({
  rows,
  sources,
}: {
  rows: FindingSourceDifference[]
  sources: FindingSourceRecord[]
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1.5">
      <p className="text-meta font-medium">
        {t('findings.sources.disagree', 'Where the sources disagree')}
      </p>
      <Table data-testid="finding-source-differences">
        <TableHeader>
          <TableRow>
            <TableHead className="w-36">{t('findings.sources.field.label', 'Field')}</TableHead>
            {sources.map((s, i) => (
              <TableHead key={i} className="min-w-32">
                <span className="font-mono">{sourceName(t, s)}</span>
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((d) => (
            <TableRow key={d.field} data-field={d.field}>
              <TableCell className="text-muted-foreground">
                {sourceFieldLabel(t, d.field ?? '')}
              </TableCell>
              {sources.map((_, i) => (
                <TableCell key={i} className="align-top">
                  <DiffValue field={d.field ?? ''} value={d.values?.[i] ?? ''} />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function SourceText({ label, text }: { label: string; text?: string }) {
  if (!text) return null
  return <UntrustedTextBlock text={text} label={label} caption={label} collapseLines={6} />
}

function SourceRecordBody({ s }: { s: FindingSourceRecord }) {
  const { t } = useTranslation()
  const n = s.native
  const extra = Object.entries(s.source_extra ?? {}).sort(([a], [b]) => a.localeCompare(b))
  return (
    <div className="mt-2 space-y-3">
      <DetailFieldGrid>
        <DetailField label={t('findings.sources.field.title', 'Title')} full>
          {s.title}
        </DetailField>
        <DetailField label={t('findings.sources.field.severity', 'Severity')}>
          {s.severity ? <SeverityBadge severity={s.severity} /> : null}
        </DetailField>
        <DetailField label={t('findings.sources.field.cvssScore', 'CVSS score')}>
          {s.cvss_score !== undefined && s.cvss_score !== null ? (
            <span className="tabular-nums">{s.cvss_score.toFixed(1)}</span>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.sources.field.nativeId', 'Source check id')}>
          {n?.vuln_id ? (
            <span className="font-mono break-all">
              {n.scheme ? `${n.scheme} ` : ''}
              {n.vuln_id}
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.sources.field.vendorSeverity', 'Vendor severity')}>
          {n?.severity}
        </DetailField>
        <DetailField label={t('findings.sources.field.family', 'Family')}>{n?.family}</DetailField>
        <DetailField label={t('findings.sources.field.status', 'Source status')}>
          {n?.status}
        </DetailField>
        <DetailField label={t('findings.sources.field.solutionType', 'Fix type')}>
          {s.solution?.type ? s.solution.type.replace(/_/g, ' ') : null}
        </DetailField>
        <DetailField label={t('findings.sources.location', 'Location')}>
          {s.location_key ? <span className="font-mono break-all">{s.location_key}</span> : null}
        </DetailField>
        <DetailField label={t('findings.sources.vulnIds', 'Vulnerability ids')} full>
          {s.vulnerability_ids && s.vulnerability_ids.length > 0 ? (
            <span className="flex flex-wrap gap-1.5">
              {s.vulnerability_ids.map((v) => (
                <Tag key={`${v.type}:${v.id}`} label={<span className="font-mono">{v.id}</span>} />
              ))}
            </span>
          ) : null}
        </DetailField>
      </DetailFieldGrid>
      <SourceText label={t('findings.sources.description', 'Description')} text={s.description} />
      <SourceText
        label={t('findings.sources.recommendation', 'Recommendation')}
        text={s.recommendation}
      />
      <SourceText label={t('findings.sources.message', 'Message')} text={s.message} />
      <SourceText label={t('findings.sources.snippet', 'Snippet')} text={s.snippet} />
      {s.scores && s.scores.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-meta text-muted-foreground">
            {t('findings.sources.scores', 'Scores')}
          </p>
          <ul className="space-y-2">
            {s.scores.map((sc, i) => (
              <ScoreRow
                key={`${sc.system}-${sc.version ?? ''}-${i}`}
                score={{
                  system: sc.system ?? '',
                  version: sc.version,
                  vector: sc.vector,
                  value: sc.value,
                  label: sc.label,
                  source: sc.source,
                  asOf: sc.as_of,
                }}
              />
            ))}
          </ul>
        </div>
      )}
      {extra.length > 0 && (
        <DetailDisclosure
          summary={t('findings.sources.otherFields', 'Other source fields ({count})', {
            count: extra.length,
          })}
        >
          <KeyValueList
            className="mt-2"
            items={extra.map(([k, v]) => ({
              key: k,
              label: k,
              value: <span className="whitespace-pre-wrap">{v}</span>,
            }))}
          />
        </DetailDisclosure>
      )}
    </div>
  )
}

function SourceRow({ s }: { s: FindingSourceRecord }) {
  const { t } = useTranslation()
  const name = sourceName(t, s)
  return (
    <li className="space-y-1 py-3 first:pt-0 last:pb-0" data-testid="finding-source-record">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-mono text-body font-medium">
          {s.tool_version ? `${name} ${s.tool_version}` : name}
        </span>
        {s.primary ? (
          <Badge variant="secondary" className="text-xs font-normal" data-slot="source-primary">
            {t('findings.sources.primary', 'Shown on the finding')}
          </Badge>
        ) : null}
        {s.backfilled ? (
          <Badge variant="outline" className="text-xs font-normal">
            {t('findings.seenBy.backfilled', 'From earlier records')}
          </Badge>
        ) : null}
        {s.truncated ? (
          <Badge variant="outline" className="text-xs font-normal">
            {t('findings.sources.truncated', 'Shortened to the size limit')}
          </Badge>
        ) : null}
      </div>
      <p className="flex flex-wrap gap-x-3 text-meta text-muted-foreground">
        <span>{sourceVia(t, s)}</span>
        <span>
          {t('findings.seenBy.first', 'First')} <RelativeTime date={s.first_seen_at} />
        </span>
        <span>
          {t('findings.seenBy.last', 'Last')} <RelativeTime date={s.last_seen_at} />
        </span>
      </p>
      <DetailDisclosure
        summary={t('findings.sources.show', 'What {source} reported', { source: name })}
      >
        <SourceRecordBody s={s} />
      </DetailDisclosure>
    </li>
  )
}

export function FindingSourceRecords({
  findingId,
  className,
}: {
  findingId: string
  className?: string
}) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useFindingSources(findingId)
  useSettleSignal(isLoading)

  if (isLoadFailure(error)) {
    return (
      <SectionLoadError
        title={t('findings.sources.loadTitle', 'what each source reported')}
        onRetry={() => void mutate()}
        className={className}
      />
    )
  }
  const rows = data?.data ?? []
  if (error || rows.length < 2) return null
  const primary = rows.find((s) => s.primary)
  const diffs = data?.differences ?? []

  return (
    <DetailSection
      title={t('findings.sources.title', 'Reported by {count} sources', { count: rows.length })}
      icon={Layers}
      className={className}
    >
      <p className="text-meta text-muted-foreground">
        {primary
          ? t(
              'findings.sources.helpPrimary',
              'The finding shows what {tool} reported first. Other sources only fill what it left empty; each keeps its own values below.',
              { tool: sourceName(t, primary) }
            )
          : t(
              'findings.sources.help',
              'Other sources only fill what the finding left empty; each keeps its own values below.'
            )}
      </p>
      {diffs.length > 0 ? (
        <DifferencesTable rows={diffs} sources={rows} />
      ) : (
        <p className="text-meta" data-testid="finding-sources-agree">
          {t('findings.sources.agree', 'The sources agree on severity, score and identity.')}
        </p>
      )}
      <ul className="divide-y" data-testid="finding-source-records">
        {rows.map((s, i) => (
          <SourceRow
            key={`${s.channel}-${s.sensor?.id ?? ''}-${s.sender ?? ''}-${s.tool ?? ''}-${i}`}
            s={s}
          />
        ))}
      </ul>
    </DetailSection>
  )
}
