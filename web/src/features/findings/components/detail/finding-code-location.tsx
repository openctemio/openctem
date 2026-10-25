'use client'

/**
 * Where in the code a finding sits: file and lines, branch and commit, the
 * snippet with the finding's line highlighted, a copy button and a link to the
 * file at that commit. The one renderer of a finding's code location, used by
 * the drawer (compact), the Overview tab and triage mode (research/276).
 *
 * Snippets are untrusted scanner text: CodeHighlighter renders React text
 * only. A secret finding's snippet arrives masked from ingest; this component
 * never sees the value.
 */

import * as React from 'react'
import { Check, Copy, ExternalLink, FileCode2 } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { copyToClipboard } from '@/lib/clipboard'
import { safeHref } from '@/lib/safe-href'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { buildRepositoryCodeUrl } from '../../lib/repository-url'
import type { FindingDetail } from '../../types'
import { CodeHighlighter } from './code-highlighter'

/** The fields a code location needs; FindingDetail and triage both map to it. */
export interface CodeLocation {
  filePath?: string
  startLine?: number
  endLine?: number
  snippet?: string
  contextSnippet?: string
  contextStartLine?: number
  repositoryUrl?: string
  branch?: string
  commitSha?: string
}

export function codeLocationOf(finding: FindingDetail): CodeLocation {
  return {
    filePath: finding.filePath,
    startLine: finding.startLine,
    endLine: finding.endLine,
    snippet: finding.snippet,
    contextSnippet: finding.contextSnippet,
    contextStartLine: finding.contextStartLine,
    repositoryUrl: finding.repositoryUrl || finding.assets?.[0]?.url,
    branch: finding.branch,
    commitSha: finding.commitSha,
  }
}

/** True when there is something to show: a file path or a snippet. */
export function hasCodeLocation(loc: CodeLocation): boolean {
  return Boolean(loc.filePath || loc.snippet || loc.contextSnippet)
}

/** Sources whose location is a URL, shown by the drawer's HTTP evidence. */
const WEB_SOURCES = new Set(['dast', 'easm'])

/**
 * Whether the drawer shows the code location band. Not for a secret (its
 * panel names the file and shows the masked value), a web finding (the
 * location is a URL; the HTTP evidence shows it) or a finding with a data
 * flow (the trace lists each step's file and line).
 */
export function showDrawerCodeLocation(finding: FindingDetail): boolean {
  if (finding.source === 'secret' || finding.findingType === 'secret') return false
  if (WEB_SOURCES.has(finding.source)) return false
  if (finding.dataFlow?.steps?.length) return false
  return hasCodeLocation(codeLocationOf(finding))
}

export interface FindingCodeLocationProps {
  location: CodeLocation
  /** Drawer layout: the snippet without its wider context, a shorter pane. */
  compact?: boolean
  className?: string
}

export function FindingCodeLocation({ location, compact, className }: FindingCodeLocationProps) {
  const { t } = useTranslation()
  const [copied, setCopied] = React.useState(false)
  const withContext = !compact && Boolean(location.contextSnippet)
  const code = withContext ? location.contextSnippet : location.snippet || location.contextSnippet
  const firstLine = withContext
    ? location.contextStartLine || 1
    : location.snippet
      ? location.startLine || 1
      : location.contextStartLine || 1
  const lines =
    location.startLine && location.startLine > 0
      ? location.endLine && location.endLine !== location.startLine
        ? `${location.startLine}-${location.endLine}`
        : String(location.startLine)
      : ''
  const repoUrl = buildRepositoryCodeUrl({
    repositoryUrl: location.repositoryUrl,
    filePath: location.filePath,
    startLine: location.startLine,
    endLine: location.endLine,
    branch: location.branch,
    commitSha: location.commitSha,
  })
  const href = repoUrl ? safeHref(repoUrl) : undefined

  const copy = React.useCallback(async () => {
    if (code && (await copyToClipboard(code))) {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    }
  }, [code])

  if (!hasCodeLocation(location)) return null

  return (
    <DetailSection
      title={t('findings.overviewTab.codeLocation', 'Code location')}
      icon={FileCode2}
      className={className}
      actions={
        href ? (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
          >
            {t('findings.overviewTab.viewInRepo', 'View in repository')}
            <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        ) : undefined
      }
    >
      <div className="space-y-2" data-testid="finding-code-location">
        {location.filePath && (
          <p className="font-mono text-sm [overflow-wrap:anywhere]" dir="ltr">
            {toDisplayText(location.filePath, 1000)}
            {lines && <span className="text-muted-foreground">:{lines}</span>}
          </p>
        )}
        {(location.branch || location.commitSha) && (
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
            {location.branch && (
              <span>
                {t('findings.overviewTab.branch', 'Branch')}{' '}
                <span className="font-mono">{toDisplayText(location.branch, 200)}</span>
              </span>
            )}
            {location.commitSha && (
              <span>
                {t('findings.overviewTab.commit', 'Commit')}{' '}
                <span className="font-mono">{location.commitSha.slice(0, 10)}</span>
              </span>
            )}
          </div>
        )}
        {code && (
          <div className="overflow-hidden rounded-lg border bg-muted/30">
            <div className="flex items-center justify-between border-b bg-muted/50 px-3 py-1.5">
              <span className="text-xs text-muted-foreground">
                {withContext
                  ? t('findings.overviewTab.snippetCtx', 'Snippet with context')
                  : t('findings.overviewTab.snippet', 'Snippet')}
              </span>
              <button
                type="button"
                onClick={() => void copy()}
                className="rounded-sm p-1 text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                aria-label={
                  copied
                    ? t('findings.evidenceItems.copiedAria', 'Copied')
                    : t('findings.overviewTab.copyCode', 'Copy code')
                }
              >
                {copied ? (
                  <Check className="h-3.5 w-3.5" aria-hidden />
                ) : (
                  <Copy className="h-3.5 w-3.5" aria-hidden />
                )}
              </button>
            </div>
            <div className={cn('overflow-auto p-3', compact ? 'max-h-64' : 'max-h-96')}>
              <CodeHighlighter
                code={code}
                filePath={location.filePath}
                className="bg-transparent"
                showLineNumbers
                startLine={firstLine}
                highlightLine={location.startLine}
              />
            </div>
          </div>
        )}
      </div>
    </DetailSection>
  )
}
