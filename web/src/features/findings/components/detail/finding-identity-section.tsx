'use client'

/**
 * "Why this is one finding": the recipe that keyed the finding, in plain
 * words from the names of the fields its key was built from, the tools that
 * reported it and the duplicates merged into it that the caller may see.
 * The API returns field names only, never a key, fingerprint or value
 * (api/docs/architecture/deduplication.md, "Why a finding is one").
 */

import { Fingerprint } from 'lucide-react'
import Link from '@/components/link'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import {
  DetailChipList,
  DetailField,
  DetailFieldGrid,
  DetailSection,
} from '@/features/shared/components/detail-sheet'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { dateFnsLocaleFor } from '@/features/shared/components/activity-timeline'
import { useFindingIdentity, type FindingIdentity } from '../../api/use-finding-identity'
import { SectionLoadError, isLoadFailure } from './section-load-error'

type T = ReturnType<typeof useTranslation>['t']

/** The plain-language name of one identity field. */
export function identityFieldLabel(t: T, name: string): string {
  switch (name) {
    case 'asset':
      return t('findings.identity.field.asset', 'asset')
    case 'component':
      return t('findings.identity.field.component', 'package without version')
    case 'vuln':
      return t('findings.identity.field.vuln', 'vulnerability')
    case 'rule':
      return t('findings.identity.field.rule', 'rule')
    case 'path':
      return t('findings.identity.field.path', 'file path')
    case 'snippet':
      return t('findings.identity.field.snippet', 'flagged code')
    case 'logical':
      return t('findings.identity.field.logical', 'function or class')
    case 'occurrence':
      return t('findings.identity.field.occurrence', 'occurrence of the same code')
    case 'line':
      return t('findings.identity.field.line', 'line')
    case 'secret':
      return t('findings.identity.field.secret', 'secret (keyed hash)')
    case 'mask':
      return t('findings.identity.field.mask', 'masked secret (keyed hash)')
    case 'type':
      return t('findings.identity.field.type', 'secret type')
    case 'method':
      return t('findings.identity.field.method', 'HTTP method')
    case 'url':
      return t('findings.identity.field.url', 'URL pattern')
    case 'params':
      return t('findings.identity.field.params', 'parameter names')
    case 'port':
      return t('findings.identity.field.port', 'port and protocol')
    case 'policy':
      return t('findings.identity.field.policy', 'policy')
    case 'resource':
      return t('findings.identity.field.resource', 'resource')
    case 'message':
      return t('findings.identity.field.message', 'message')
    case 'campaign':
      return t('findings.identity.field.campaign', 'pentest campaign')
    case 'title':
      return t('findings.identity.field.title', 'title')
    default:
      return name
  }
}

/** The name of the recipe ("Package vulnerability", "Manual finding key"). */
export function identityAlgoLabel(t: T, algo: string): string {
  switch (algo) {
    case 'v2/sca':
      return t('findings.identity.algo.sca', 'Package vulnerability')
    case 'v2/sast':
      return t('findings.identity.algo.sast', 'Code issue')
    case 'v2/secret':
      return t('findings.identity.algo.secret', 'Secret')
    case 'v2/dast':
      return t('findings.identity.algo.dast', 'Web application issue')
    case 'v2/network':
      return t('findings.identity.algo.network', 'Network vulnerability')
    case 'v2/misconfig':
      return t('findings.identity.algo.misconfig', 'Misconfiguration')
    case 'v1/ingest':
      return t('findings.identity.algo.ingestV1', 'Earlier scanner key')
    case 'manual/v1':
      return t('findings.identity.algo.manualV1', 'Manual finding key')
    case 'pentest/v1':
      return t('findings.identity.algo.pentestV1', 'Pentest finding key')
    default:
      return algo
  }
}

function mergeReasonLabel(t: T, reason: string): string {
  switch (reason) {
    case 'manual':
      return t('findings.identity.reason.manual', 'marked duplicate by a person')
    case 'asset_merge':
      return t('findings.identity.reason.assetMerge', 'assets merged')
    case 'refingerprint':
      return t('findings.identity.reason.refingerprint', 'same key after re-keying')
    case 'dast_identity_repair':
      return t('findings.identity.reason.dastRepair', 'web finding key repaired')
    default:
      return t('findings.identity.reason.other', 'merged')
  }
}

/** The explanation itself, for a loaded response. */
export function FindingIdentityView({ identity }: { identity: FindingIdentity }) {
  const { t, locale } = useTranslation()
  const fields = identity.fields.map((f) => identityFieldLabel(t, f))
  const when = (iso: string) => {
    const d = new Date(iso)
    return Number.isNaN(d.getTime())
      ? ''
      : new Intl.DateTimeFormat(locale, { dateStyle: 'medium' }).format(d)
  }

  let rule: React.ReactNode
  if (identity.legacy) {
    rule = t(
      'findings.identity.legacy',
      'This finding was keyed by an earlier recipe that was not recorded. It moves to the current recipe the next time a scanner reports it.'
    )
  } else if (fields.length > 0) {
    rule = t('findings.identity.sentence', 'Findings are one when they share: {fields}', {
      fields: fields.join(t('findings.identity.fieldSeparator', ', ')),
    })
  } else if (identity.algo === 'v1/ingest') {
    rule = t(
      'findings.identity.ingestV1',
      'Findings are one when the earlier scanner key matches: the asset with the reported rule, location, package or vulnerability, depending on the finding type. It moves to the current recipe the next time a scanner reports it.'
    )
  } else {
    rule = t('findings.identity.unknown', 'The rule that keyed this finding is not recorded.')
  }

  return (
    <DetailFieldGrid>
      <DetailField label={t('findings.identity.rule', 'Rule')} full>
        <span className="block">{rule}</span>
        {identity.algo && !identity.legacy && (
          <span className="mt-1 block text-xs text-muted-foreground">
            {identityAlgoLabel(t, identity.algo)}
          </span>
        )}
      </DetailField>
      <DetailField label={t('findings.identity.sources', 'Reported by')} full>
        <DetailChipList
          label={t('findings.identity.sources', 'Reported by')}
          empty={t('findings.identity.noSources', 'No tool recorded')}
          chips={identity.sources.map((s) => ({
            key: s.tool,
            label: s.tool,
            meta: s.last_seen_at ? (
              <RelativeTime
                date={s.last_seen_at}
                locale={dateFnsLocaleFor(locale)}
                className="text-xs"
              />
            ) : undefined,
          }))}
        />
      </DetailField>
      <DetailField label={t('findings.identity.merged', 'Merged duplicates')} full>
        {identity.merged.length === 0 ? (
          <span className="text-sm text-muted-foreground">
            {t('findings.identity.noMerged', 'No other finding was merged into this one')}
          </span>
        ) : (
          <ul className="space-y-1" aria-label={t('findings.identity.merged', 'Merged duplicates')}>
            {identity.merged.map((m) => (
              <li key={m.id} className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5">
                <Link
                  href={`/findings/${encodeURIComponent(m.id)}`}
                  className="font-mono text-xs underline-offset-2 hover:underline"
                >
                  {m.id.slice(0, 8)}
                </Link>
                {m.tool_name && <span className="text-muted-foreground">· {m.tool_name}</span>}
                <span className="text-muted-foreground">· {mergeReasonLabel(t, m.reason)}</span>
                {when(m.merged_at) && (
                  <span className="text-muted-foreground">· {when(m.merged_at)}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </DetailField>
    </DetailFieldGrid>
  )
}

export function FindingIdentitySection({ findingId }: { findingId: string }) {
  const { t } = useTranslation()
  const { identity, isLoading, error, mutate } = useFindingIdentity(findingId)
  const title = t('findings.identity.heading', 'Why this is one finding')

  if (error) {
    // A refusal (403/404) hides the section: no oracle about the finding.
    return isLoadFailure(error) ? (
      <DetailSection title={title} icon={Fingerprint}>
        <SectionLoadError
          title={t('findings.detail.section.identity', 'the identity explanation')}
          onRetry={() => void mutate()}
        />
      </DetailSection>
    ) : null
  }
  if (!isLoading && !identity) return null
  return (
    <DetailSection title={title} icon={Fingerprint}>
      {isLoading || !identity ? (
        <div className="space-y-2" aria-busy="true">
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-7 w-1/2" />
        </div>
      ) : (
        <FindingIdentityView identity={identity} />
      )}
    </DetailSection>
  )
}
