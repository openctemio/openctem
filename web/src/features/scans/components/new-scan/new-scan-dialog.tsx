/**
 * New Scan Dialog
 *
 * Creates a scan through the shared scan wizard (scan-wizard.tsx): every
 * step can be opened at any time, the live summary sits beside each step,
 * Create stays disabled until every step is valid and names the first
 * problem as a link to it, and Ctrl/Cmd+Enter creates. The draft is kept per
 * organization and user while the tab lives; closing with changes offers to
 * keep it. Design: research/418.
 */

'use client'

import { useEffect, useMemo, useState, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { Clock, Loader2, Play, RotateCcw, ShieldCheck } from 'lucide-react'
import { submitScanApproval, useScanApprovalPreview } from '@/lib/api/scan-approval-hooks'
import { ApprovalRequirement, missingEvidence } from '../approval/approval-requirement'
import { toZonePreviewRequest, triggerErrorHint } from '@/features/scan-zones'
import { ReviewStep } from './review-step'
import { useScanReview } from '../../hooks/use-scan-review'
import { useScanWorkflow, useScanWorkflows } from '@/lib/api/scan-workflow-hooks'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'
import { useAuthStore } from '@/stores/auth-store'
import { useDebounce } from '@/hooks/use-debounce'

import { type ScanWizardStep } from './scan-stepper'
import { ScanWizard, useWizardSteps } from './scan-wizard'
import { ScanSummaryContent, summaryLine } from './scan-summary'
import { BasicInfoStep } from './basic-info-step'
import { TargetsStep } from './targets-step'
import { OptionsStep } from './options-step'
import { ScheduleStep } from './schedule-step'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../types'
import { directTargets, formDataToCreateRequest, onceRunAt } from '../../lib/scan-form'
import { issueCount, scanStepIssues } from '../../lib/wizard-validity'
import { getErrorMessage } from '@/lib/api/error-handler'
import { post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import { notifyScannerConfigWarnings } from '../../lib/scanner-config-warnings'
import { useCreateScanConfig, invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import {
  probeNewAssetsRequest,
  probeNote,
  savedProbeOutcome,
  type ProbeOutcome,
} from '../../lib/continuous-discovery'
import { useTranslation } from '@/context/i18n-provider'
import {
  refusedFromError,
  scopeRefusalSummary,
  ScopeRefusalPanel,
  type ScopeRefusal,
} from '@/features/scope'
import { useTargetsCheck } from '../../hooks/use-targets-check'
import { useWorkflowReadiness } from '../../hooks/use-workflow-readiness'
import { isFormDirty } from '../../lib/form-dirty'
import { useDiscardPrompt } from './wizard-chrome'
import { useTenant } from '@/context/tenant-provider'
import {
  clearNewScanDraft,
  loadNewScanDraft,
  saveNewScanDraft,
} from '../../hooks/use-new-scan-draft'
import { onlyAwaitingApproval } from '../../lib/scope-wait'

interface NewScanDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSubmit?: (data: NewScanFormData) => void
}

const STEPS: ScanWizardStep[] = ['basic', 'targets', 'options', 'schedule', 'review']

/** What the approval preview is asked about this scan. */
function approvalRequestOf(form: NewScanFormData) {
  const req = formDataToCreateRequest(form)
  return {
    targets: directTargets(form),
    asset_group_ids: req.asset_group_ids ?? [],
    scan_type: req.scan_type,
    scanner_name: req.scanner_name,
    scan_workflow_id: req.scan_workflow_id,
    schedule_type: req.schedule_type,
    sensor_preference: req.sensor_preference,
    scan_zone_id: req.scan_zone_id ?? undefined,
  }
}

export function NewScanDialog({ open, onOpenChange, onSubmit }: NewScanDialogProps) {
  const nav = useWizardSteps('basic')
  const currentStep = nav.step
  const setCurrentStep = nav.setStep
  const [formData, setFormData] = useState<NewScanFormData>(DEFAULT_NEW_SCAN)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [restoredDraft, setRestoredDraft] = useState(false)
  // Targets the server refused on create (TARGET_OUT_OF_SCOPE details).
  const [refused, setRefused] = useState<ScopeRefusal[]>([])
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  const userId = useAuthStore((s) => s.user?.id)

  // Keep the wizard while the user leaves it (to approve a scope entry,
  // verify a domain) and give it back on the next open.
  const restored = useRef(false)
  const restartNav = nav.reset
  useEffect(() => {
    if (!open) {
      restored.current = false
      return
    }
    if (restored.current) return
    restored.current = true
    const draft = loadNewScanDraft(tenantId, userId)
    if (draft && STEPS.includes(draft.step as ScanWizardStep)) {
      const form = { ...DEFAULT_NEW_SCAN, ...draft.form }
      setFormData(form)
      restartNav(draft.step as ScanWizardStep)
      setRestoredDraft(isFormDirty(form, DEFAULT_NEW_SCAN))
    }
  }, [open, tenantId, userId, restartNav])
  useEffect(() => {
    if (open && restored.current && formData !== DEFAULT_NEW_SCAN)
      saveNewScanDraft(tenantId, { form: formData, step: currentStep }, userId)
  }, [open, tenantId, userId, formData, currentStep])

  // The same check the Targets step shows (one cached request); when every
  // refused target only waits for a scope approval, the scan can be saved to
  // start once it is approved.
  const { check: scopeCheck, readiness, sent } = useTargetsCheck(formData, open)
  const awaitingApproval = onlyAwaitingApproval(scopeCheck.results)

  // Store created scan config ID for triggering
  const createdConfigIdRef = useRef<string | null>(null)

  // API hooks
  const { trigger: createScanConfig, isMutating: isCreating } = useCreateScanConfig()

  // Scan zones (RFC-023): the picker and routing preview appear once the
  // team has zones and the user may read them.
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  // Run now needs scans:execute on top of the scans:write that creates it.
  const canExecute = useHasPermission(Permission.ScansExecute)
  const router = useRouter()
  // The probing workflow's readiness: whether it waits for a sensor.
  const { data: probeWorkflows } = useScanWorkflows(
    open && formData.continuousProbeWorkflowId
      ? { is_active: true, per_page: 100, include: 'readiness' }
      : null,
    { revalidateOnFocus: false }
  )
  const { data: zonesData } = useScanZones(canReadZones && open)
  const zones = useMemo(() => zonesData?.data ?? [], [zonesData?.data])
  // The previews take names: the picked assets by name, with the typed ones.
  const previewRequest = useMemo(
    () =>
      toZonePreviewRequest(
        { ...formDataToCreateRequest(formData), targets: directTargets(formData) },
        formData.scanZoneId
      ),
    [formData]
  )

  const workflowRequest = useMemo(
    () => ({
      scan_workflow_id: formData.workflowId ?? '',
      targets: previewRequest.targets,
      asset_group_ids: previewRequest.asset_group_ids,
      scan_zone_id: formData.scanZoneId ?? undefined,
      depth: formData.depth,
    }),
    [formData.workflowId, formData.scanZoneId, formData.depth, previewRequest]
  )

  // Every step's problems, from the same checks the API repeats on create.
  const workflowReadiness = useWorkflowReadiness(formData, open)
  const issues = useMemo(() => scanStepIssues(formData, { readiness, t }), [formData, readiness, t])
  const stepProblems = issueCount(issues, STEPS)
  // The Review's answers (scope, workflow preview) once the form is complete,
  // so Create and Ctrl/Cmd+Enter know from any step whether the scan may start.
  const review = useScanReview(
    formData,
    workflowRequest,
    open && (currentStep === 'review' || stepProblems === 0)
  )
  // Scope changes elsewhere (an entry approved, a domain verified, a sensor
  // online): the Review answers from a fresh check each time it opens.
  const recheckScope = review.scope.recheck
  useEffect(() => {
    if (open && currentStep === 'review') void recheckScope()
  }, [open, currentStep, recheckScope])

  // Scan approval (RFC-073): what the organization's rules ask of this scan.
  // Asked as soon as there is something to scan (debounced), so the summary
  // says before Review whether an approval is needed; the form is on Review.
  const [approvalJustification, setApprovalJustification] = useState('')
  const [approvalTicket, setApprovalTicket] = useState('')
  const hasTargets =
    formData.targets.customTargets.length +
      formData.targets.assetIds.length +
      formData.targets.assetGroupIds.length >
    0
  const approvalJSON = useDebounce(
    open && hasTargets ? JSON.stringify(approvalRequestOf(formData)) : '',
    600
  )
  const approvalInput = useMemo(
    () =>
      approvalJSON ? (JSON.parse(approvalJSON) as ReturnType<typeof approvalRequestOf>) : null,
    [approvalJSON]
  )
  const { data: approval } = useScanApprovalPreview(approvalInput)
  const needsApproval = !!approval?.required
  const approvalLack = missingEvidence(t, approval, approvalJustification, approvalTicket)
  const { data: chosenWorkflow } = useScanWorkflow(
    formData.mode === 'workflow' && formData.workflowId ? formData.workflowId : null,
    { revalidateOnFocus: false }
  )
  const whatLabel =
    formData.mode === 'workflow'
      ? (chosenWorkflow?.name ?? t('scans.new.workflowFallback'))
      : formData.scannerName || t('scans.new.scannerFallback')
  const blocked = review.blockers.length > 0
  // Saving to start when the scope is approved: the scope refusal is not a
  // blocker then, every other one still is.
  const waitBlocked = review.blockers.length > (review.refused.length > 0 ? 1 : 0)
  // "Scan the N allowed targets, skip the rest": only refused targets block,
  // and some are allowed. The server re-checks and records the skipped ones.
  const canSkipRefused =
    review.refused.length > 0 && review.allowedCount > 0 && review.otherBlockers.length === 0
  // The review's answers are on their way: Create waits for them.
  const reviewPending = review.scope.isLoading && !review.scope.results
  const canCreate =
    stepProblems === 0 &&
    !reviewPending &&
    !approvalLack &&
    (awaitingApproval ? !waitBlocked : !blocked)

  const handleDataChange = (data: Partial<NewScanFormData>) => {
    // Step settings belong to the workflow they were made for.
    setFormData((prev) => ({
      ...prev,
      ...data,
      ...('workflowId' in data && data.workflowId !== prev.workflowId ? { stepParams: {} } : {}),
    }))
    if (data.targets) setRefused([])
  }

  const startLabel =
    formData.schedule.runImmediately && canExecute
      ? t('scans.new.startScan')
      : formData.schedule.saveOnly
        ? t('scans.new.saveScan')
        : t('scans.new.scheduleScan')

  const startOver = () => {
    clearNewScanDraft(tenantId, userId)
    setRefused([])
    setFormData(DEFAULT_NEW_SCAN)
    setRestoredDraft(false)
    nav.reset()
    createdConfigIdRef.current = null
  }

  const handleSubmit = async (opts: { waitForScope?: boolean; skipRefused?: boolean } = {}) => {
    nav.setAttempted(true)
    if (stepProblems > 0) return
    if (opts.skipRefused ? !canSkipRefused : opts.waitForScope ? waitBlocked : blocked) {
      toast.error(review.blockers[0])
      return
    }
    if (approvalLack) {
      setCurrentStep('review')
      return
    }

    setIsSubmitting(true)
    try {
      // Map form data to API request format
      const request = formDataToCreateRequest(formData)
      if (opts.waitForScope) request.start_when_scope_approved = true
      if (opts.skipRefused) request.skip_refused_targets = true

      // Create the scan configuration
      const scanConfig = await createScanConfig(request)

      if (!scanConfig) {
        throw new Error(t('scans.new.createFailedNoConfig'))
      }
      notifyScannerConfigWarnings(scanConfig, t)

      createdConfigIdRef.current = scanConfig.id

      // Continuous discovery: the probing scan is saved with the passive one
      // (active, only assets new since its last run).
      let probeOutcome: ProbeOutcome | null = null
      if (formData.continuousProbeWorkflowId) {
        const probe = probeNewAssetsRequest(
          { ...request, targets: directTargets(formData) },
          formData.continuousProbeWorkflowId,
          t('scans.new.continuousSecondName', undefined, { name: formData.name.trim() })
        )
        if (probe) {
          try {
            await createScanConfig(probe)
            probeOutcome = savedProbeOutcome(
              probeWorkflows?.data?.find((w) => w.id === formData.continuousProbeWorkflowId)
                ?.readiness?.state
            )
          } catch (probeError) {
            probeOutcome = {
              kind: 'failed',
              error: getErrorMessage(probeError, t('scans.new.unknownError')),
            }
          }
        }
      }

      // One result for the pair: the probe's news joins the success toast.
      const note = probeNote(probeOutcome, t)
      const done = (message: string, description?: string) => {
        const text = [description, note.description].filter(Boolean).join(' ') || undefined
        const opts = {
          description: text,
          ...(note.sensorsHref
            ? {
                action: {
                  label: t('scans.new.continuousProbeSensors'),
                  onClick: () => router.push(note.sensorsHref as string),
                },
              }
            : {}),
        }
        if (note.variant === 'warning') toast.warning(message, opts)
        else toast.success(message, opts)
      }

      const waits = !!(scanConfig as { starts_when_scope_approved?: boolean })
        .starts_when_scope_approved
      if (needsApproval) {
        // Saved; submit it for approval. It runs once approved (when the
        // user asked to run now) or at its schedule.
        try {
          await submitScanApproval(scanConfig.id, {
            justification: approvalJustification.trim(),
            ticket: approvalTicket.trim(),
            run_on_approval: formData.schedule.runImmediately && canExecute,
          })
          done(
            t('scans.approval.submitted', 'Saved "{name}" and submitted it for approval', {
              name: formData.name,
            })
          )
        } catch (submitError) {
          toast.error(
            t(
              'scans.approval.submitFailed',
              'Saved "{name}", but it was not submitted for approval: {error}',
              { name: formData.name, error: getErrorMessage(submitError, '') }
            )
          )
        }
      } else if (waits) {
        done(
          t('scans.new.savedWaiting', undefined, { name: formData.name }),
          t('scans.new.savedWaitingHint')
        )
      } else if (formData.schedule.runImmediately && canExecute) {
        // Trigger scan immediately if requested (and the user may run scans)
        try {
          await post(scanEndpoints.trigger(scanConfig.id), {})
          done(t('scans.new.started', undefined, { name: formData.name }))
        } catch (triggerError) {
          // Scan config was created but trigger failed - show specific error
          const triggerRefused = refusedFromError(triggerError)
          const triggerErrorMsg =
            triggerRefused.length > 0
              ? scopeRefusalSummary(t, triggerRefused)
              : getErrorMessage(triggerError, t('scans.new.unknownError'))
          console.error('Failed to trigger scan:', triggerError)

          // Show a persistent error toast with action buttons
          toast.error(
            t('scans.new.createdButNotStarted', undefined, {
              name: formData.name,
              error: triggerErrorMsg,
            }),
            {
              duration: 10000, // Keep visible for 10 seconds
              action: {
                label: t('scans.new.viewScan'),
                onClick: () => {
                  router.push(`/scans/${scanConfig.id}`)
                },
              },
              description: triggerErrorHint(triggerError) ?? t('scans.new.triggerManually'),
            }
          )

          // Still close dialog and refresh - the scan was created successfully
          clearNewScanDraft(tenantId, userId)
          await invalidateScanConfigsCache()
          onSubmit?.(formData)
          setFormData(DEFAULT_NEW_SCAN)
          nav.reset()
          createdConfigIdRef.current = null
          onOpenChange(false)
          return
        }
      } else if (formData.schedule.saveOnly) {
        done(t('scans.new.savedStartLater', undefined, { name: formData.name }))
      } else {
        const at = formData.schedule.frequency === 'once' ? onceRunAt(formData) : null
        done(
          at
            ? t('scans.new.willRunOn', undefined, {
                name: formData.name,
                time: at.toLocaleString(),
              })
            : t('scans.new.scheduled', undefined, { name: formData.name })
        )
      }

      // Invalidate caches to refresh lists
      await invalidateScanConfigsCache()

      // Call optional callback
      onSubmit?.(formData)

      // Reset and close
      clearNewScanDraft(tenantId, userId)
      setFormData(DEFAULT_NEW_SCAN)
      nav.reset()
      createdConfigIdRef.current = null
      onOpenChange(false)
    } catch (error) {
      const scopeRefused = refusedFromError(error)
      if (scopeRefused.length > 0) {
        // Show each refused target with its fixes, on the step that owns them.
        setRefused(scopeRefused)
        setCurrentStep('targets')
        return
      }
      console.error('Failed to create scan:', error)
      toast.error(getErrorMessage(error, t('scans.new.createFailed')))
    } finally {
      setIsSubmitting(false)
    }
  }

  const isLoading = isSubmitting || isCreating

  const close = () => {
    startOver()
    onOpenChange(false)
  }
  // Keep as draft: closes; the draft stays for the next open in this tab.
  const keep = () => onOpenChange(false)
  const { requestClose, prompt: discardPrompt } = useDiscardPrompt(
    () => isFormDirty(formData, DEFAULT_NEW_SCAN),
    close,
    keep
  )

  const renderStep = () => {
    switch (currentStep) {
      case 'basic':
        return <BasicInfoStep data={formData} onChange={handleDataChange} />
      case 'targets':
        return (
          <>
            {refused.length > 0 && (
              <ScopeRefusalPanel refused={refused} className="mx-4 mt-4 sm:mx-6" />
            )}
            <TargetsStep data={formData} onChange={handleDataChange} />
          </>
        )
      case 'options':
        return (
          <OptionsStep
            data={formData}
            onChange={handleDataChange}
            showProfile
            workflowRequest={workflowRequest}
          />
        )
      case 'schedule':
        return <ScheduleStep data={formData} onChange={handleDataChange} offerSaveOnly />
      case 'review':
        return (
          <ReviewStep
            data={formData}
            onChange={handleDataChange}
            review={review}
            onEdit={setCurrentStep}
            whatLabel={whatLabel}
            zones={zones}
            canReadZones={canReadZones}
            zoneRequest={previewRequest}
            approvalBlock={
              approval ? (
                <ApprovalRequirement
                  evaluation={approval}
                  justification={approvalJustification}
                  ticket={approvalTicket}
                  onJustification={setApprovalJustification}
                  onTicket={setApprovalTicket}
                />
              ) : null
            }
          />
        )
      default:
        return null
    }
  }

  const results = scopeCheck.results ?? []
  const refusedCount = results.filter((r) => !r.allowed).length
  const summaryFacts = {
    data: formData,
    whatLabel,
    directCount: sent.length,
    ready: scopeCheck.results ? results.length - refusedCount : undefined,
    blocked: scopeCheck.results ? refusedCount : undefined,
    checking: scopeCheck.available && scopeCheck.isLoading && !scopeCheck.results,
    approval,
    workflowReadiness,
    issues,
    steps: STEPS,
    shownSteps: nav.attempted ? new Set(STEPS) : nav.seen,
    onGo: setCurrentStep,
  }

  // Why Create is disabled when no step has a problem (the Review's answers).
  const isLast = currentStep === 'review'
  const reviewNote =
    stepProblems > 0 || !isLast
      ? undefined
      : awaitingApproval
        ? t('scans.new.waitNotice')
        : blocked
          ? review.blockers[0]
          : approvalLack || undefined

  return (
    <ScanWizard
      open={open}
      onRequestClose={requestClose}
      title={t('scans.new.title')}
      description={t('scans.new.description')}
      steps={STEPS}
      step={currentStep}
      onStepChange={setCurrentStep}
      issues={issues}
      attempted={nav.attempted}
      seen={nav.seen}
      summary={<ScanSummaryContent {...summaryFacts} />}
      summaryLine={summaryLine(summaryFacts, t)}
      banner={
        restoredDraft ? (
          <div
            className="mx-4 mt-4 flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-sm sm:mx-6"
            role="status"
            data-testid="draft-restored"
          >
            <span>{t('scans.wizard.draftRestored')}</span>
            <Button type="button" variant="ghost" size="sm" onClick={startOver}>
              <RotateCcw className="me-1.5 h-4 w-4" aria-hidden />
              {t('scans.wizard.startOver')}
            </Button>
          </div>
        ) : null
      }
      canSubmit={canCreate}
      onSubmit={() => void handleSubmit(awaitingApproval ? { waitForScope: true } : {})}
      note={reviewNote}
      noteTone={!awaitingApproval && (blocked || approvalLack) ? 'destructive' : 'muted'}
      isLoading={isLoading}
      after={discardPrompt}
      primary={
        <>
          {!awaitingApproval && blocked && canSkipRefused && stepProblems === 0 && (
            <Button
              type="button"
              variant="secondary"
              onClick={() => void handleSubmit({ skipRefused: true })}
              disabled={isLoading || !!approvalLack}
              className="h-auto whitespace-normal py-2"
              data-testid="skip-refused"
            >
              {t('scans.review.skipRefused', 'Scan the {count} allowed targets, skip the rest', {
                count: review.allowedCount,
              })}
            </Button>
          )}
          {awaitingApproval ? (
            <Button
              type="button"
              onClick={() => void handleSubmit({ waitForScope: true })}
              disabled={isLoading || !canCreate}
              className="h-auto whitespace-normal py-2"
              aria-describedby="wizard-note"
              data-testid="wizard-create"
            >
              {isLoading ? (
                <Loader2 className="me-2 h-4 w-4 shrink-0 animate-spin" />
              ) : (
                <Clock className="me-2 h-4 w-4 shrink-0" />
              )}
              {t('scans.new.createWhenApproved')}
            </Button>
          ) : (
            <Button
              type="button"
              onClick={() => void handleSubmit()}
              disabled={isLoading || !canCreate}
              aria-describedby="wizard-note"
              aria-keyshortcuts="Control+Enter Meta+Enter"
              data-testid="wizard-create"
            >
              {isLoading ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  {formData.schedule.runImmediately
                    ? t('scans.common.starting')
                    : t('scans.common.saving')}
                </>
              ) : needsApproval ? (
                <>
                  <ShieldCheck className="me-2 h-4 w-4" />
                  {t('scans.approval.submitForApproval', 'Submit for approval')}
                </>
              ) : (
                <>
                  <Play className="me-2 h-4 w-4" />
                  {startLabel}
                </>
              )}
            </Button>
          )}
        </>
      }
    >
      {renderStep()}
    </ScanWizard>
  )
}
