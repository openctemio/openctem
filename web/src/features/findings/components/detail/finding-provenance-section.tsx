'use client'

/**
 * Provenance: where and when the finding was seen. The first sighting
 * (branch @commit, the pipeline and merge request when the caller may read
 * CI runs), the latest one, every branch it is on with its first and last
 * commit, and the recent pipelines. Commits and pipelines link out only to
 * http(s) URLs.
 */

import { ExternalLink, GitBranch } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import {
  DetailField,
  DetailFieldGrid,
  DetailSection,
} from '@/features/shared/components/detail-sheet'
import type { FindingDetail, FindingRunSighting } from '../../types'
import {
  buildRepositoryCommitUrl,
  repositoryUrlFromName,
  safeHttpUrl,
} from '../../lib/repository-url'

function Commit({ sha, repo }: { sha?: string; repo?: string }) {
  if (!sha) return null
  const short = sha.slice(0, 8)
  const href = buildRepositoryCommitUrl(repo, sha)
  return href ? (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className="font-mono text-xs underline-offset-2 hover:underline"
    >
      @{short}
    </a>
  ) : (
    <span className="font-mono text-xs">@{short}</span>
  )
}

export function FindingProvenanceSection({ finding }: { finding: FindingDetail }) {
  const { t, locale } = useTranslation()
  const p = finding.provenance
  if (!p) return null
  const asset = finding.assets[0]
  const repo =
    finding.repositoryUrl ||
    (asset?.type === 'repository' ? repositoryUrlFromName(asset.name) : undefined)
  const when = (iso?: string) => {
    if (!iso) return ''
    const d = new Date(iso)
    return Number.isNaN(d.getTime())
      ? ''
      : new Intl.DateTimeFormat(locale, { dateStyle: 'medium' }).format(d)
  }
  const run = (r: FindingRunSighting) => {
    const href = safeHttpUrl(r.pipelineUrl)
    const label = r.externalRunId
      ? t('findings.provenance.pipeline', 'Pipeline #{id}', { id: r.externalRunId })
      : t('findings.provenance.run', 'CI run')
    return (
      <span className="inline-flex flex-wrap items-center gap-x-1.5">
        {href ? (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="inline-flex items-center gap-1 underline-offset-2 hover:underline"
          >
            {label}
            <ExternalLink className="h-3 w-3 text-muted-foreground" aria-hidden />
          </a>
        ) : (
          <span>{label}</span>
        )}
        {r.pullRequest && (
          <span className="text-muted-foreground">
            {t('findings.provenance.mergeRequest', 'MR !{id}', { id: r.pullRequest })}
          </span>
        )}
      </span>
    )
  }

  const first = p.firstRun
  const firstBranch = first?.branch || p.firstDetectedBranch
  const firstCommit = first?.commitSha || p.firstDetectedCommit
  // The branch occurrences are authoritative for "last seen": the newest one.
  const newest = [...p.branches].sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt))[0]
  const lastBranch = newest?.name || p.lastSeenBranch
  const lastCommit = newest?.lastCommit || p.lastSeenCommit
  const otherTool =
    p.lastSeenTool && finding.toolName && p.lastSeenTool !== finding.toolName
      ? p.lastSeenTool
      : undefined

  if (!firstBranch && !lastBranch && p.branches.length === 0 && p.runs.length === 0) return null

  return (
    <DetailSection title={t('findings.provenance.heading', 'Provenance')} icon={GitBranch}>
      <DetailFieldGrid>
        {firstBranch && (
          <DetailField label={t('findings.provenance.firstSeen', 'First seen')} full>
            <span className="inline-flex flex-wrap items-center gap-x-1.5">
              <span className="font-medium">{firstBranch}</span>
              <Commit sha={firstCommit} repo={repo} />
              {first && <span className="text-muted-foreground">· {when(first.createdAt)}</span>}
              {first && <>· {run(first)}</>}
            </span>
          </DetailField>
        )}
        {lastBranch && (
          <DetailField label={t('findings.provenance.lastSeen', 'Last seen')} full>
            <span className="inline-flex flex-wrap items-center gap-x-1.5">
              <span className="font-medium">{lastBranch}</span>
              <Commit sha={lastCommit} repo={repo} />
              {newest && <span className="text-muted-foreground">· {when(newest.lastSeenAt)}</span>}
              {otherTool && (
                <span className="text-muted-foreground">
                  · {t('findings.provenance.byTool', 'by {tool}', { tool: otherTool })}
                </span>
              )}
            </span>
          </DetailField>
        )}
        {p.branches.length > 0 && (
          <DetailField
            label={t('findings.provenance.branches', 'On {count} branches', {
              count: p.branches.length,
            })}
            full
          >
            <ul className="space-y-1">
              {p.branches.map((b) => (
                <li key={b.name} className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
                  <span className="font-medium">{b.name}</span>
                  {b.isDefault && (
                    <Badge variant="secondary" className="h-5 px-1.5 text-[11px]">
                      {t('findings.provenance.default', 'default')}
                    </Badge>
                  )}
                  <Commit sha={b.firstCommit} repo={repo} />
                  {b.lastCommit && b.lastCommit !== b.firstCommit && (
                    <>
                      <span className="text-muted-foreground" aria-hidden>
                        →
                      </span>
                      <Commit sha={b.lastCommit} repo={repo} />
                    </>
                  )}
                  {b.status !== 'open' && (
                    <span className="text-xs text-muted-foreground">
                      ·{' '}
                      {b.status === 'auto_fixed'
                        ? t('findings.provenance.fixedHere', 'fixed here')
                        : t('findings.provenance.resolvedHere', 'resolved here')}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </DetailField>
        )}
        {p.runs.length > 0 && (
          <DetailField label={t('findings.provenance.recentRuns', 'Recent pipelines')} full>
            <ul className="space-y-1">
              {p.runs.map((r) => (
                <li key={r.id} className="flex flex-wrap items-center gap-x-1.5">
                  {run(r)}
                  {r.branch && <span className="text-muted-foreground">· {r.branch}</span>}
                  <Commit sha={r.commitSha} repo={repo} />
                  <span className="text-muted-foreground">· {when(r.createdAt)}</span>
                </li>
              ))}
            </ul>
          </DetailField>
        )}
      </DetailFieldGrid>
    </DetailSection>
  )
}
