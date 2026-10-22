'use client'

import { toDisplayText } from '@/lib/untrusted-text'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import {
  LogIn,
  ArrowRight,
  AlertTriangle,
  Shield,
  FileCode,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  ExternalLink,
} from 'lucide-react'
import { useState } from 'react'
import type { FindingDetail, DataFlowLocation, DataFlowLocationType } from '../../types'
import { DATA_FLOW_LOCATION_CONFIG } from '../../types'
import { buildRepositoryCodeUrl } from '../../lib/repository-url'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import { CodeHighlighter } from './code-highlighter'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { SafeExternalLink } from '@/components/safe-external-link'
import { useTranslation } from '@/context/i18n-provider'

interface DataFlowTabProps {
  finding: FindingDetail
}

// Fixed accents: the code panel follows the highlighter's dark theme in both
// modes, and each step role keeps its own colour.
const STYLE = {
  codePanel: 'border-slate-700/50 bg-[#1e1e2e]', // palette-ok: code panel, highlighter theme
  codeHeader: 'border-slate-700/50 bg-slate-800/50', // palette-ok: code panel, highlighter theme
  codeHeaderText: 'text-slate-400', // palette-ok: code panel, highlighter theme
  ok: 'text-green-400', // palette-ok: success and remediation accent
  fn: 'bg-cyan-500/10 text-cyan-400', // palette-ok: function accent
  cls: 'bg-purple-500/10 text-purple-400', // palette-ok: class accent
  guidance: 'border-green-500/20 bg-green-500/5', // palette-ok: remediation accent
}

const STEP_BORDER: Record<DataFlowLocationType, string> = {
  source: 'border-blue-500', // palette-ok: step-role accent
  intermediate: 'border-yellow-500', // palette-ok: step-role accent
  sanitizer: 'border-green-500', // palette-ok: step-role accent
  sink: 'border-red-500', // palette-ok: step-role accent
}

const CARD_BORDER: Record<DataFlowLocationType, string> = {
  source: 'border-blue-500/30', // palette-ok: step-role accent
  intermediate: 'border-yellow-500/30', // palette-ok: step-role accent
  sanitizer: 'border-green-500/30', // palette-ok: step-role accent
  sink: 'border-red-500/30', // palette-ok: step-role accent
}

function LocationIcon({ type }: { type: DataFlowLocationType }) {
  switch (type) {
    case 'source':
      return <LogIn className="h-4 w-4" aria-hidden />
    case 'sink':
      return <AlertTriangle className="h-4 w-4" aria-hidden />
    case 'sanitizer':
      return <Shield className="h-4 w-4" aria-hidden />
    default:
      return <ArrowRight className="h-4 w-4" aria-hidden />
  }
}

function useCopyToClipboard() {
  const [copied, setCopied] = useState(false)
  const copy = async (text: string) => {
    await copyToClipboard(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return { copied, copy }
}

/**
 * The link to a step's file at the commit the trace was reported for. Only
 * with that commit: a link to a branch, or to the finding's latest commit,
 * could show other code than the trace is about.
 */
function stepFileUrl(finding: FindingDetail, step: DataFlowLocation): string | null {
  const commitSha = finding.dataFlow?.commitSha
  if (!commitSha || !step.path) return null
  return buildRepositoryCodeUrl({
    repositoryUrl: finding.repositoryUrl || finding.assets[0]?.url,
    filePath: step.path,
    startLine: step.line,
    endLine: step.endLine,
    commitSha,
  })
}

function DataFlowStepCard({
  step,
  position,
  isLast,
  fileUrl,
}: {
  step: DataFlowLocation
  position: number
  isLast: boolean
  fileUrl: string | null
}) {
  const { t } = useTranslation()
  const [isExpanded, setIsExpanded] = useState(true)
  const config = DATA_FLOW_LOCATION_CONFIG[step.type] ?? DATA_FLOW_LOCATION_CONFIG.intermediate
  const { copied, copy } = useCopyToClipboard()
  const typeLabel = t(config.labelKey)
  const fileLocation = step.path ? `${step.path}${step.line ? `:${step.line}` : ''}` : ''

  return (
    <li className="relative">
      {!isLast && (
        <div
          className="absolute start-6 top-14 h-[calc(100%-3.5rem)] w-0.5 bg-border"
          aria-hidden
        />
      )}
      <div className="flex gap-3">
        <div
          className={cn(
            'flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full border-2',
            config.bgColor,
            STEP_BORDER[step.type]
          )}
        >
          <LocationIcon type={step.type} />
        </div>

        <div className="mb-4 min-w-0 flex-1">
          <div className={cn('w-full rounded-lg border transition-colors', CARD_BORDER[step.type])}>
            <button
              type="button"
              onClick={() => setIsExpanded(!isExpanded)}
              aria-expanded={isExpanded}
              className="w-full rounded-t-lg p-4 text-start transition-colors hover:bg-muted/30"
            >
              <div className="mb-2 flex items-center justify-between gap-2">
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <Badge className={cn('border-0 text-xs', config.bgColor, config.color)}>
                    {t('findings.dataFlow.step', 'Step {n}: {type}', {
                      n: position + 1,
                      type: typeLabel,
                    })}
                  </Badge>
                  {step.label && (
                    <code className="break-all rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
                      {toDisplayText(step.label)}
                    </code>
                  )}
                </div>
                {isExpanded ? (
                  <ChevronDown
                    className="h-4 w-4 flex-shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                ) : (
                  <ChevronRight
                    className="h-4 w-4 flex-shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                )}
              </div>
              {step.path && (
                <div className="flex min-w-0 items-center gap-2 text-sm">
                  <FileCode
                    className="h-3.5 w-3.5 flex-shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                  <span className="truncate font-mono text-primary">
                    {toDisplayText(step.path)}
                  </span>
                  {step.line ? (
                    <span className="font-mono text-muted-foreground">:{step.line}</span>
                  ) : null}
                </div>
              )}
            </button>

            {isExpanded && (
              <div className="space-y-3 px-4 pb-4">
                {fileUrl && (
                  <SafeExternalLink
                    href={fileUrl}
                    className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                  >
                    {t('findings.dataFlow.viewAtCommit', 'View this line at the scanned commit')}
                    <ExternalLink className="h-3 w-3" aria-hidden />
                  </SafeExternalLink>
                )}
                {step.content && (
                  <div className="group relative">
                    <div className={cn('overflow-hidden rounded-md border', STYLE.codePanel)}>
                      <div
                        className={cn(
                          'flex items-center justify-between border-b px-3 py-1.5',
                          STYLE.codeHeader
                        )}
                      >
                        <span className={cn('truncate font-mono text-xs', STYLE.codeHeaderText)}>
                          {step.path?.split('/').pop() || t('findings.dataFlow.code', 'code')}
                          {step.line ? `:${step.line}` : ''}
                        </span>
                        <div className="flex items-center gap-1">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6 opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
                                aria-label={t('findings.dataFlow.copyCode', 'Copy code')}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  copy(step.content || '')
                                }}
                              >
                                {copied ? (
                                  <Check className={cn('h-3 w-3', STYLE.ok)} aria-hidden />
                                ) : (
                                  <Copy className="h-3 w-3" aria-hidden />
                                )}
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent side="top">
                              {copied
                                ? t('findings.dataFlow.copied', 'Copied')
                                : t('findings.dataFlow.copyCode', 'Copy code')}
                            </TooltipContent>
                          </Tooltip>
                          {fileLocation && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-6 w-6 opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
                                  aria-label={t('findings.dataFlow.copyPath', 'Copy file and line')}
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    copy(fileLocation)
                                  }}
                                >
                                  <FileCode className="h-3 w-3" aria-hidden />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent side="top">
                                {t('findings.dataFlow.copyPath', 'Copy file and line')}
                              </TooltipContent>
                            </Tooltip>
                          )}
                        </div>
                      </div>
                      <div className="overflow-x-auto p-3">
                        <CodeHighlighter
                          code={step.content}
                          filePath={step.path}
                          className="bg-transparent"
                        />
                      </div>
                    </div>
                  </div>
                )}
                {(step.functionName || step.className) && (
                  <div className="flex flex-wrap gap-3 text-xs">
                    {step.functionName && (
                      <div className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
                        <span>{t('findings.dataFlow.function', 'Function')}</span>
                        <code className={cn('break-all rounded px-1.5 py-0.5', STYLE.fn)}>
                          {toDisplayText(step.functionName)}
                        </code>
                      </div>
                    )}
                    {step.className && (
                      <div className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
                        <span>{t('findings.dataFlow.class', 'Class')}</span>
                        <code className={cn('break-all rounded px-1.5 py-0.5', STYLE.cls)}>
                          {step.className}
                        </code>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </li>
  )
}

function DataFlowSummary({ steps }: { steps: DataFlowLocation[] }) {
  const { t } = useTranslation()
  const count = (type: DataFlowLocationType) => steps.filter((s) => s.type === type).length
  const tiles: Array<{ key: string; label: string; value: number; className: string }> = [
    {
      key: 'source',
      label: t('findings.dataFlow.sources', 'Sources'),
      value: count('source'),
      className: 'border-blue-500/30 bg-blue-500/10 text-blue-400', // palette-ok: step-role accent
    },
    {
      key: 'intermediate',
      label: t('findings.dataFlow.propagation', 'Propagation steps'),
      value: count('intermediate'),
      className: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400', // palette-ok: step-role accent
    },
    {
      key: 'sanitizer',
      label: t('findings.dataFlow.sanitizers', 'Sanitizers'),
      value: count('sanitizer'),
      className: 'border-green-500/30 bg-green-500/10 text-green-400', // palette-ok: step-role accent
    },
    {
      key: 'sink',
      label: t('findings.dataFlow.sinks', 'Sinks'),
      value: count('sink'),
      className: 'border-red-500/30 bg-red-500/10 text-red-400', // palette-ok: step-role accent
    },
  ]
  return (
    <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
      {tiles.map((tile) => (
        <div key={tile.key} className={cn('rounded-lg border p-3', tile.className)}>
          <p className="mb-1 text-xs text-muted-foreground">{tile.label}</p>
          <p className="text-2xl font-bold">{tile.value}</p>
        </div>
      ))}
    </div>
  )
}

export function DataFlowTab({ finding }: DataFlowTabProps) {
  const { t } = useTranslation()
  const steps = finding.dataFlow?.steps ?? []

  if (steps.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center">
        <div className="mb-4 rounded-full bg-muted p-4">
          <ArrowRight className="h-8 w-8 text-muted-foreground" aria-hidden />
        </div>
        <h3 className="mb-2 text-lg font-semibold">
          {t('findings.dataFlow.emptyTitle', 'No data flow')}
        </h3>
        <p className="max-w-md text-sm text-muted-foreground">
          {t('findings.dataFlow.empty', 'This scanner did not report a data flow')}
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">
        {t(
          'findings.dataFlow.hint',
          'How untrusted data reaches the vulnerable code, from source to sink.'
        )}
      </p>

      <DataFlowSummary steps={steps} />

      <Separator />

      <div>
        <h3 className="mb-4 text-lg font-semibold">
          {t('findings.dataFlow.path', 'Data flow path')}
        </h3>
        <ol className="space-y-0">
          {steps.map((step, i) => (
            <DataFlowStepCard
              key={`${step.type}-${i}`}
              step={step}
              position={i}
              isLast={i === steps.length - 1}
              fileUrl={stepFileUrl(finding, step)}
            />
          ))}
        </ol>
      </div>

      <Separator />

      <div className={cn('rounded-lg border p-4', STYLE.guidance)}>
        <h4 className="mb-2 flex items-center gap-2 font-semibold">
          <Shield className={cn('h-4 w-4', STYLE.ok)} aria-hidden />
          {t('findings.dataFlow.guidanceTitle', 'Remediation guidance')}
        </h4>
        <ul className="ms-2 list-inside list-disc space-y-1 text-sm text-muted-foreground">
          <li>
            {t(
              'findings.dataFlow.guidanceSource',
              'At the source: validate input as soon as it is received.'
            )}
          </li>
          <li>
            {t(
              'findings.dataFlow.guidanceSink',
              'Before the sink: use parameterized queries, escaping or encoding.'
            )}
          </li>
          <li>
            {t(
              'findings.dataFlow.guidanceSanitizer',
              'Add a sanitizer: transform the data to a safe form before it is used.'
            )}
          </li>
        </ul>
      </div>
    </div>
  )
}
