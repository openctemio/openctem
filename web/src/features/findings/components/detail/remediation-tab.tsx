'use client'

import { StatusLozenge } from '@/components/ui/status-lozenge'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  ExternalLink,
  CheckCircle2,
  Circle,
  Loader,
  Loader2,
  Wrench,
  Link,
  ListChecks,
  XCircle,
  Gauge,
  Timer,
  Code2,
  Zap,
  Copy,
  Check,
  Wand2,
  Target,
  Plus,
  X,
} from 'lucide-react'
import { useState, useMemo, useCallback } from 'react'
import { toast } from 'sonner'
import { mutate as globalMutate } from 'swr'
import { copyToClipboard } from '@/lib/clipboard'
import { usePermissions } from '@/context/permission-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Input } from '@/components/ui/input'
import { useAddRemediationStep } from '../../api/use-finding-evidence'
import type { Remediation, RemediationStepStatus, FindingDetail } from '../../types'
import { CodeHighlighter } from './code-highlighter'
import { MobilizationBriefCard } from './mobilization-brief-card'
import { buildRepositoryCodeUrl } from '../../lib/repository-url'
import { SafeExternalLink } from '@/components/safe-external-link'
import { useTranslation } from '@/context/i18n-provider'

interface RemediationTabProps {
  remediation: Remediation
  finding?: FindingDetail // Optional: for extended remediation info
}

const STATUS_ICONS: Record<RemediationStepStatus, React.ReactNode> = {
  pending: <Circle className="text-muted-foreground h-4 w-4" />,
  in_progress: <Loader className="h-4 w-4 animate-spin text-warning" />,
  completed: <CheckCircle2 className="h-4 w-4 text-success" />,
}

// Effort level badges
// Effort ids; the label is translated at render (findings.remediationTab.effort.<id>).
const EFFORT_CONFIG: Record<string, { label: string; color: string }> = {
  trivial: { label: 'Trivial', color: 'border-success/50 text-success' },
  low: { label: 'Low', color: 'border-success/50 text-success' },
  medium: { label: 'Medium', color: 'border-warning/50 text-warning' },
  high: { label: 'High', color: 'border-destructive/50 text-destructive' },
}

export function RemediationTab({ remediation, finding }: RemediationTabProps) {
  const { t, locale } = useTranslation()
  const [copiedCode, setCopiedCode] = useState(false)

  const { hasPermission } = usePermissions()
  const canWrite = hasPermission('findings:write')
  const findingId = finding?.id ?? null
  const { trigger: addStep, isMutating: addingStep } = useAddRemediationStep(findingId)

  // Steps are plain strings. Seed the display from the finding's remediation
  // steps; once the operator appends one, the POST returns the full updated
  // array which takes over (stepsOverride) so the list stays in sync without a
  // dedicated GET endpoint.
  const [stepsOverride, setStepsOverride] = useState<string[] | null>(null)
  const [showStepForm, setShowStepForm] = useState(false)
  const [newStep, setNewStep] = useState('')

  const handleCopyCode = async (code: string) => {
    await copyToClipboard(code)
    setCopiedCode(true)
    setTimeout(() => setCopiedCode(false), 2000)
  }

  const handleAddStep = useCallback(async () => {
    const trimmed = newStep.trim()
    if (!trimmed) {
      toast.error(t('findings.remediationTab.stepRequired', 'Step text is required'))
      return
    }
    try {
      const res = await addStep({ step: trimmed })
      setStepsOverride(res.steps)
      setNewStep('')
      setShowStepForm(false)
      toast.success(t('findings.remediationTab.stepAdded', 'Remediation step added'))
      // Refresh the finding so a reload/other consumers pick up the new step.
      if (findingId) {
        void globalMutate(`/api/v1/findings/${findingId}`)
      }
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('findings.remediationTab.stepAddFailed', 'Failed to add remediation step')
        )
      )
    }
  }, [newStep, addStep, findingId, t])

  // Get data from apiRemediation JSONB (primary) or fallback to direct fields
  const apiRemed = finding?.apiRemediation
  const fixCode = apiRemed?.fix_code || finding?.fixCode
  const fixRegex = apiRemed?.fix_regex || finding?.fixRegex
  const isAutoFixable = apiRemed?.auto_fixable || (fixCode && fixCode.length > 0)
  const isFixAvailable = apiRemed?.fix_available || isAutoFixable
  const effort = apiRemed?.effort
  const remediationSteps = apiRemed?.steps || []
  const displaySteps = stepsOverride ?? remediationSteps
  const remediationReferences = apiRemed?.references || remediation.references || []
  const recommendation = apiRemed?.recommendation || remediation.description

  // Build repository code URL for "View in Repository" link
  // Repository URL available but not yet rendered — add link when repository detail page is ready.
  const _repositoryCodeUrl = useMemo(() => {
    // Use repositoryUrl directly, or fall back to asset URL
    const repoUrl = finding?.repositoryUrl || finding?.assets?.[0]?.url
    return buildRepositoryCodeUrl({
      repositoryUrl: repoUrl,
      filePath: finding?.filePath,
      startLine: finding?.startLine,
      endLine: finding?.endLine,
      branch: finding?.branch,
      commitSha: finding?.commitSha,
    })
  }, [
    finding?.repositoryUrl,
    finding?.assets,
    finding?.filePath,
    finding?.startLine,
    finding?.endLine,
    finding?.branch,
    finding?.commitSha,
  ])

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString(locale, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
  }

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2)
  }

  return (
    <div className="space-y-6">
      {/* Remediation Context - from finding extended data and apiRemediation JSONB */}
      {(finding?.remediationType ||
        finding?.estimatedFixTime !== undefined ||
        finding?.fixComplexity ||
        finding?.remedyAvailable !== undefined ||
        effort ||
        isFixAvailable ||
        isAutoFixable) && (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 sm:gap-4">
          {/* Fix Available */}
          {isFixAvailable !== undefined && (
            <div className="bg-muted/50 rounded-lg p-3">
              <p className="text-muted-foreground text-xs mb-1">
                {t('findings.remediationTab.fixAvailable', 'Fix Available')}
              </p>
              <div className="flex items-center gap-1.5">
                {isFixAvailable ? (
                  <>
                    <CheckCircle2 className="h-3.5 w-3.5 text-success" />
                    <span className="font-medium text-success">
                      {t('findings.remediationTab.yes', 'Yes')}
                    </span>
                  </>
                ) : (
                  <>
                    <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="font-medium text-muted-foreground">
                      {t('findings.remediationTab.no', 'No')}
                    </span>
                  </>
                )}
              </div>
            </div>
          )}

          {/* Auto-fixable */}
          {isAutoFixable !== undefined && (
            <div className="bg-muted/50 rounded-lg p-3">
              <p className="text-muted-foreground text-xs mb-1">
                {t('findings.remediationTab.autoFixableLabel', 'Auto-fixable')}
              </p>
              <div className="flex items-center gap-1.5">
                {isAutoFixable ? (
                  <>
                    <Wand2 className="h-3.5 w-3.5 text-success" />
                    <span className="font-medium text-success">
                      {t('findings.remediationTab.yes', 'Yes')}
                    </span>
                  </>
                ) : (
                  <>
                    <Target className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="font-medium text-muted-foreground">
                      {t('findings.remediationTab.manual', 'Manual')}
                    </span>
                  </>
                )}
              </div>
            </div>
          )}

          {/* Effort */}
          {effort && (
            <div className="bg-muted/50 rounded-lg p-3">
              <p className="text-muted-foreground text-xs mb-1">
                {t('findings.remediationTab.effort', 'Effort')}
              </p>
              <Badge
                variant="outline"
                className={`capitalize ${EFFORT_CONFIG[effort]?.color || ''}`}
              >
                {EFFORT_CONFIG[effort]
                  ? t(`findings.remediationTab.effort.${effort}`, EFFORT_CONFIG[effort].label)
                  : effort}
              </Badge>
            </div>
          )}

          {/* Fix Complexity */}
          {finding?.fixComplexity && (
            <div className="bg-muted/50 rounded-lg p-3">
              <p className="text-muted-foreground text-xs mb-1">
                {t('findings.remediationTab.fixComplexity', 'Fix Complexity')}
              </p>
              <div className="flex items-center gap-1.5">
                <Gauge className="h-3.5 w-3.5" />
                <Badge
                  variant="outline"
                  className={`capitalize ${
                    finding.fixComplexity === 'complex'
                      ? 'border-destructive/50 text-destructive'
                      : finding.fixComplexity === 'moderate'
                        ? 'border-warning/50 text-warning'
                        : 'border-success/50 text-success'
                  }`}
                >
                  {finding.fixComplexity}
                </Badge>
              </div>
            </div>
          )}

          {/* Remediation Type */}
          {finding?.remediationType && (
            <div className="bg-muted/50 rounded-lg p-3">
              <p className="text-muted-foreground text-xs mb-1">
                {t('findings.remediationTab.remType', 'Remediation Type')}
              </p>
              <Badge variant="outline" className="capitalize">
                {finding.remediationType}
              </Badge>
            </div>
          )}

          {/* Estimated Fix Time */}
          {finding?.estimatedFixTime !== undefined && (
            <div className="bg-muted/50 rounded-lg p-3">
              <p className="text-muted-foreground text-xs mb-1">
                {t('findings.remediationTab.estTime', 'Estimated Fix Time')}
              </p>
              <div className="flex items-center gap-1.5">
                <Timer className="h-3.5 w-3.5" />
                <span className="font-medium">
                  {finding.estimatedFixTime >= 60
                    ? `${Math.floor(finding.estimatedFixTime / 60)}h ${finding.estimatedFixTime % 60}m`
                    : `${finding.estimatedFixTime}m`}
                </span>
              </div>
            </div>
          )}

          {/* Remedy Available (legacy field) */}
          {finding?.remedyAvailable !== undefined && !isFixAvailable && (
            <div className="bg-muted/50 rounded-lg p-3">
              <p className="text-muted-foreground text-xs mb-1">
                {t('findings.remediationTab.remedyAvail', 'Remedy Available')}
              </p>
              <div className="flex items-center gap-1.5">
                {finding.remedyAvailable ? (
                  <>
                    <CheckCircle2 className="h-3.5 w-3.5 text-success" />
                    <span className="font-medium text-success">
                      {t('findings.remediationTab.yes', 'Yes')}
                    </span>
                  </>
                ) : (
                  <>
                    <XCircle className="h-3.5 w-3.5 text-warning" />
                    <span className="font-medium text-warning">
                      {t('findings.remediationTab.no', 'No')}
                    </span>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Description / Recommended Fix */}
      <div>
        <h3 className="mb-3 flex items-center gap-2 font-semibold">
          <Wrench className="h-4 w-4" />
          {t('findings.remediationTab.recommendation', 'Recommendation')}
        </h3>
        {recommendation && recommendation !== 'No recommendation provided by scanner.' ? (
          <div className="rounded-lg border bg-muted/30 p-4">
            <p className="text-sm whitespace-pre-wrap leading-relaxed">{recommendation}</p>
          </div>
        ) : (
          <div className="rounded-lg border border-dashed p-4 text-center">
            <p className="text-muted-foreground text-sm">
              {t('findings.remediation.none', 'The scanner gave no remediation advice.')}
            </p>
          </div>
        )}
      </div>

      {/* CTEM Mobilization: definition of done + acceptable fixes */}
      <MobilizationBriefCard
        findingId={findingId}
        canWrite={canWrite}
        brief={{
          successCriteria: apiRemed?.success_criteria,
          verificationMethod: apiRemed?.verification_method,
          preferredFix: apiRemed?.preferred_fix,
          alternativeFixes: apiRemed?.alternative_fixes,
        }}
      />

      {/* Auto-Fix Code Section */}
      {(fixCode || fixRegex) && (
        <div>
          <h3 className="mb-3 flex items-center gap-2 font-semibold">
            <Code2 className="h-4 w-4" />
            {t('findings.remediationTab.autoFixCode', 'Auto-Fix Code')}
            {isAutoFixable && (
              <StatusLozenge
                tone="resolved"
                icon={Zap}
                label={t('findings.remediationTab.autoFixable', 'Auto-fixable')}
                className="ms-2"
              />
            )}
          </h3>

          {fixCode && (
            <div className="relative">
              <div className="bg-[#1e1e2e] rounded-lg overflow-hidden border border-slate-700/50">
                {/* Header with copy button */}
                <div className="flex items-center justify-between px-3 py-2 bg-slate-800/50 border-b border-slate-700/30">
                  <span className="text-xs text-muted-foreground font-mono">
                    {t('findings.remediationTab.fixCode', 'Fix Code')}
                  </span>
                  <button
                    onClick={() => handleCopyCode(fixCode)}
                    className="text-slate-400 hover:text-slate-200 transition-colors p-1 rounded"
                    title={t('findings.remediationTab.copyCode', 'Copy code')}
                  >
                    {copiedCode ? (
                      <Check className="h-3 w-3 text-success" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                  </button>
                </div>
                {/* Code content */}
                <ScrollArea className="max-h-[400px]">
                  <div className="p-3">
                    <CodeHighlighter
                      code={fixCode.trim()}
                      className="bg-transparent"
                      showLineNumbers={true}
                    />
                  </div>
                </ScrollArea>
              </div>
              <p className="text-muted-foreground text-xs mt-2">
                {t(
                  'findings.remediationTab.suggested',
                  'This code fix was suggested by the scanner. Review carefully before applying.'
                )}
              </p>
            </div>
          )}

          {fixRegex && (
            <div className="mt-4 bg-[#1e1e2e] rounded-lg overflow-hidden border border-slate-700/50">
              <div className="px-3 py-2 bg-slate-800/50 border-b border-slate-700/30">
                <span className="text-xs text-muted-foreground font-mono">
                  {t('findings.remediationTab.regexPattern', 'Regex-based fix pattern')}
                </span>
              </div>
              <div className="p-4 space-y-3 font-mono text-sm">
                <div className="flex items-start gap-2">
                  <span className="text-muted-foreground shrink-0">
                    {t('findings.remediationTab.pattern', 'Pattern:')}
                  </span>
                  <code className="bg-muted px-2 py-1 rounded text-warning break-all">
                    {fixRegex.regex}
                  </code>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-muted-foreground shrink-0">
                    {t('findings.remediationTab.replace', 'Replace:')}
                  </span>
                  <code className="bg-muted px-2 py-1 rounded text-success break-all">
                    {fixRegex.replacement}
                  </code>
                </div>
                {fixRegex.count !== undefined && fixRegex.count > 0 && (
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground">
                      {t('findings.remediationTab.occurrences', 'Occurrences:')}
                    </span>
                    <Badge variant="outline" className="border-slate-600 text-slate-300">
                      {fixRegex.count}
                    </Badge>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Remediation Steps - from apiRemediation JSONB or legacy UI */}
      {(displaySteps.length > 0 || remediation.steps.length > 0 || canWrite) && (
        <>
          <Separator />

          <div>
            <div className="mb-3 flex items-center justify-between">
              <h3 className="flex items-center gap-2 font-semibold">
                <ListChecks className="h-4 w-4" />
                {t('findings.remediationTab.steps', 'Remediation Steps')}
              </h3>
              {canWrite && !showStepForm && (
                <Button size="sm" variant="outline" onClick={() => setShowStepForm(true)}>
                  <Plus className="me-2 h-4 w-4" />
                  {t('findings.remediationTab.addStep', 'Add Step')}
                </Button>
              )}
            </div>

            {/* Add-step inline form */}
            {canWrite && showStepForm && (
              <div className="mb-3 flex items-center gap-2">
                <Input
                  value={newStep}
                  onChange={(e) => setNewStep(e.target.value)}
                  placeholder={t(
                    'findings.remediationTab.stepPlaceholder',
                    'Describe a remediation step…'
                  )}
                  disabled={addingStep}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault()
                      void handleAddStep()
                    }
                  }}
                  autoFocus
                />
                <Button size="sm" onClick={handleAddStep} disabled={addingStep || !newStep.trim()}>
                  {addingStep ? (
                    <Loader2 className="me-1.5 h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Plus className="me-1.5 h-3.5 w-3.5" />
                  )}
                  {t('findings.remediationTab.add', 'Add')}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setNewStep('')
                    setShowStepForm(false)
                  }}
                  disabled={addingStep}
                >
                  <X className="h-3.5 w-3.5" />
                  <span className="sr-only">{t('findings.remediationTab.cancel', 'Cancel')}</span>
                </Button>
              </div>
            )}

            {/* Steps from apiRemediation JSONB / manually added (plain strings) */}
            {displaySteps.length > 0 && (
              <div className="space-y-2">
                {displaySteps.map((step, index) => (
                  <div
                    key={index}
                    className="flex items-start gap-3 rounded-lg border bg-muted/30 p-3"
                  >
                    <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-medium text-primary">
                      {index + 1}
                    </div>
                    <p className="text-sm leading-relaxed">{step}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Empty hint when nothing tracked yet but the operator can add */}
            {displaySteps.length === 0 && remediation.steps.length === 0 && canWrite && (
              <p className="text-muted-foreground text-sm">
                {t('findings.remediationTab.noStepsYet', 'No remediation steps added yet.')}
              </p>
            )}

            {/* Legacy steps with status tracking (for manual tracking) */}
            {displaySteps.length === 0 && remediation.steps.length > 0 && (
              <div className="space-y-3">
                {remediation.steps.map((step, index) => (
                  <div key={step.id} className="flex items-start gap-3 rounded-lg border p-3">
                    <div className="flex-1 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground text-xs font-medium">
                          {t('findings.remediationTab.stepN', 'Step {n}', { n: index + 1 })}
                        </span>
                        {STATUS_ICONS[step.status]}
                        <Badge
                          variant="outline"
                          className={`text-xs ${
                            step.status === 'completed'
                              ? 'border-success/50 text-success'
                              : step.status === 'in_progress'
                                ? 'border-warning/50 text-warning'
                                : ''
                          }`}
                        >
                          {step.status === 'in_progress'
                            ? t('findings.remediationTab.status.in_progress', 'In Progress')
                            : step.status === 'completed'
                              ? t('findings.remediationTab.status.completed', 'Completed')
                              : t('findings.remediationTab.status.pending', 'Pending')}
                        </Badge>
                      </div>
                      <p
                        className={`text-sm ${step.status === 'completed' ? 'text-muted-foreground line-through' : ''}`}
                      >
                        {step.description}
                      </p>
                      {step.completedBy && step.completedAt && (
                        <div className="text-muted-foreground flex items-center gap-2 text-xs">
                          <Avatar className="h-4 w-4">
                            <AvatarFallback className="text-meta">
                              {getInitials(step.completedBy.name)}
                            </AvatarFallback>
                          </Avatar>
                          <span>
                            {t(
                              'findings.remediationTab.completedBy',
                              'Completed by {name} on {date}',
                              {
                                name: step.completedBy.name,
                                date: formatDate(step.completedAt),
                              }
                            )}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {/* References - from apiRemediation JSONB or legacy */}
      {remediationReferences.length > 0 && (
        <>
          <Separator />
          <div>
            <h3 className="mb-3 flex items-center gap-2 font-semibold">
              <Link className="h-4 w-4" />
              {t('findings.remediationTab.references', 'References')}
            </h3>
            <ul className="space-y-2">
              {remediationReferences.map((ref, index) => (
                <li key={index}>
                  <SafeExternalLink
                    href={ref}
                    className="flex items-center gap-2 text-sm text-primary hover:underline break-all"
                  >
                    <ExternalLink className="h-3 w-3 shrink-0" />
                    {ref}
                  </SafeExternalLink>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </div>
  )
}
