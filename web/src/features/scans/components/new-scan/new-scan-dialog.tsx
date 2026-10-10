/**
 * New Scan Dialog
 *
 * Multi-step wizard dialog for creating new scans.
 * Connects to the scan configuration API to create and optionally trigger scans.
 */

'use client'

import { useEffect, useMemo, useState, useRef } from 'react'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { ChevronLeft, ChevronRight, Clock, Loader2, Play, ShieldCheck } from 'lucide-react'
import { submitScanApproval, useScanApprovalPreview } from '@/lib/api/scan-approval-hooks'
import { ApprovalRequirement, missingEvidence } from '../approval/approval-requirement'
import { toZonePreviewRequest, triggerErrorHint } from '@/features/scan-zones'
import { ReviewStep } from './review-step'
import { useScanReview } from '../../hooks/use-scan-review'
import { useScanWorkflow } from '@/lib/api/scan-workflow-hooks'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import { ScanStepper, type ScanWizardStep } from './scan-stepper'
import { BasicInfoStep } from './basic-info-step'
import { TargetsStep } from './targets-step'
import { OptionsStep } from './options-step'
import { ScheduleStep } from './schedule-step'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../types'
import {
  basicInfoError,
  directTargets,
  formDataToCreateRequest,
  targetsError,
  onceRunAt,
  scheduleError,
} from '../../lib/scan-form'
import { getErrorMessage } from '@/lib/api/error-handler'
import { notifyScannerConfigWarnings } from '../../lib/scanner-config-warnings'
import { useCreateScanConfig, invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import { probeNewAssetsRequest } from '../../lib/continuous-discovery'
import { scopeCheckTier } from '../../lib/scan-intensity'
import { useTranslation } from '@/context/i18n-provider'
import {
  refusedFromError,
  scopeRefusalSummary,
  ScopeRefusalPanel,
  useScopeCheck,
  type ScopeRefusal,
} from '@/features/scope'
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

export function NewScanDialog({ open, onOpenChange, onSubmit }: NewScanDialogProps) {
  const [currentStep, setCurrentStep] = useState<ScanWizardStep>('basic')
  const [formData, setFormData] = useState<NewScanFormData>(DEFAULT_NEW_SCAN)
  const [isSubmitting, setIsSubmitting] = useState(false)
  // Targets the server refused on create (TARGET_OUT_OF_SCOPE details).
  const [refused, setRefused] = useState<ScopeRefusal[]>([])
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id

  // Keep the wizard while the user leaves it (to approve a scope entry,
  // verify a domain) and give it back on the next open.
  const restored = useRef(false)
  useEffect(() => {
    if (!open) {
      restored.current = false
      return
    }
    if (restored.current) return
    restored.current = true
    const draft = loadNewScanDraft(tenantId)
    if (draft && STEPS.includes(draft.step as ScanWizardStep)) {
      setFormData({ ...DEFAULT_NEW_SCAN, ...draft.form })
      setCurrentStep(draft.step as ScanWizardStep)
    }
  }, [open, tenantId])
  useEffect(() => {
    if (open && restored.current && formData !== DEFAULT_NEW_SCAN)
      saveNewScanDraft(tenantId, { form: formData, step: currentStep })
  }, [open, tenantId, formData, currentStep])

  // The same check the Targets step shows (one cached request): when every
  // refused target only waits for a scope approval, the scan can be saved to
  // start once it is approved.
  const scopeCheck = useScopeCheck(directTargets(formData), {
    enabled: open,
    sensor_preference:
      formData.sensorPreference === 'tenant' || formData.sensorPreference === 'platform'
        ? formData.sensorPreference
        : 'auto',
    scanner_name: formData.mode === 'single' ? formData.scannerName || undefined : undefined,
    tier: scopeCheckTier(formData),
  })
  const awaitingApproval = onlyAwaitingApproval(scopeCheck.results)

  // Store created scan config ID for triggering
  const createdConfigIdRef = useRef<string | null>(null)

  // API hooks
  const { trigger: createScanConfig, isMutating: isCreating } = useCreateScanConfig()

  // Scan zones (RFC-023): the picker and routing preview appear once the
  // team has zones and the user may read them.
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
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
    }),
    [formData.workflowId, formData.scanZoneId, previewRequest]
  )
  const review = useScanReview(formData, workflowRequest, open && currentStep === 'review')

  // Scan approval (RFC-073): what the organization's rules ask of this scan,
  // shown on the review step; the scan is then saved and submitted.
  const [approvalJustification, setApprovalJustification] = useState('')
  const [approvalTicket, setApprovalTicket] = useState('')
  const approvalInput = useMemo(() => {
    if (!open || currentStep !== 'review') return null
    const req = formDataToCreateRequest(formData)
    return {
      targets: directTargets(formData),
      asset_group_ids: req.asset_group_ids ?? [],
      scan_type: req.scan_type,
      scanner_name: req.scanner_name,
      scan_workflow_id: req.scan_workflow_id,
      schedule_type: req.schedule_type,
      sensor_preference: req.sensor_preference,
      scan_zone_id: req.scan_zone_id ?? undefined,
    }
  }, [open, currentStep, formData])
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

  const currentStepIndex = STEPS.indexOf(currentStep)
  const isFirstStep = currentStepIndex === 0
  const isLastStep = currentStepIndex === STEPS.length - 1

  const handleDataChange = (data: Partial<NewScanFormData>) => {
    setFormData((prev) => ({ ...prev, ...data }))
    if (data.targets) setRefused([])
  }

  const validateCurrentStep = (): boolean => {
    switch (currentStep) {
      case 'basic': {
        const problem = basicInfoError(formData, t)
        if (problem) {
          toast.error(problem)
          return false
        }
        return true
      }
      case 'targets': {
        const problem = targetsError(formData, t)
        if (problem) {
          toast.error(problem)
          return false
        }
        return true
      }
      case 'options':
        return true
      case 'schedule': {
        const problem = scheduleError(formData, undefined, t)
        if (problem) {
          toast.error(problem)
          return false
        }
        return true
      }
      default:
        return true
    }
  }

  const handleNext = () => {
    if (!validateCurrentStep()) return

    if (!isLastStep) {
      setCurrentStep(STEPS[currentStepIndex + 1])
    }
  }

  const handleBack = () => {
    if (!isFirstStep) {
      setCurrentStep(STEPS[currentStepIndex - 1])
    }
  }

  const handleStepClick = (step: ScanWizardStep) => {
    const stepIndex = STEPS.indexOf(step)
    if (stepIndex < currentStepIndex) {
      setCurrentStep(step)
    }
  }
  const startLabel = formData.schedule.runImmediately
    ? t('scans.new.startScan')
    : formData.schedule.saveOnly
      ? t('scans.new.saveScan')
      : t('scans.new.scheduleScan')

  const handleSubmit = async (opts: { waitForScope?: boolean } = {}) => {
    if (!validateCurrentStep()) return
    if (opts.waitForScope ? waitBlocked : blocked) {
      toast.error(review.blockers[0])
      return
    }
    if (approvalLack) {
      toast.error(approvalLack)
      return
    }

    const targetProblem = targetsError(formData, t)
    if (targetProblem) {
      toast.error(targetProblem)
      setCurrentStep('targets')
      return
    }

    setIsSubmitting(true)
    try {
      // Map form data to API request format
      const request = formDataToCreateRequest(formData)
      if (opts.waitForScope) request.start_when_scope_approved = true

      // Create the scan configuration
      const scanConfig = await createScanConfig(request)

      if (!scanConfig) {
        throw new Error(t('scans.new.createFailedNoConfig'))
      }
      notifyScannerConfigWarnings(scanConfig, t)

      createdConfigIdRef.current = scanConfig.id

      // Continuous discovery: the probing scan is saved with the passive one
      // (active, only assets new since its last run).
      if (formData.continuousProbeWorkflowId) {
        const probe = probeNewAssetsRequest(
          { ...request, targets: directTargets(formData) },
          formData.continuousProbeWorkflowId,
          t('scans.new.continuousSecondName', undefined, { name: formData.name.trim() })
        )
        if (probe) {
          try {
            await createScanConfig(probe)
          } catch (probeError) {
            toast.error(
              t('scans.new.continuousSecondFailed', undefined, {
                error: getErrorMessage(probeError, t('scans.new.unknownError')),
              })
            )
          }
        }
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
            run_on_approval: formData.schedule.runImmediately,
          })
          toast.success(
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
        toast.success(t('scans.new.savedWaiting', undefined, { name: formData.name }), {
          description: t('scans.new.savedWaitingHint'),
        })
      } else if (formData.schedule.runImmediately) {
        // Trigger scan immediately if requested
        // Import trigger function dynamically to avoid hook rules issue
        const { post } = await import('@/lib/api/client')
        const { scanEndpoints } = await import('@/lib/api/endpoints')

        try {
          await post(scanEndpoints.trigger(scanConfig.id), {})
          toast.success(t('scans.new.started', undefined, { name: formData.name }))
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
                  // Navigate to the scan detail page
                  window.location.href = `/scans/${scanConfig.id}`
                },
              },
              description: triggerErrorHint(triggerError) ?? t('scans.new.triggerManually'),
            }
          )

          // Still close dialog and refresh - the scan was created successfully
          clearNewScanDraft(tenantId)
          await invalidateScanConfigsCache()
          onSubmit?.(formData)
          setFormData(DEFAULT_NEW_SCAN)
          setCurrentStep('basic')
          createdConfigIdRef.current = null
          onOpenChange(false)
          return
        }
      } else if (formData.schedule.saveOnly) {
        toast.success(t('scans.new.savedStartLater', undefined, { name: formData.name }))
      } else {
        const at = formData.schedule.frequency === 'once' ? onceRunAt(formData) : null
        toast.success(
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
      clearNewScanDraft(tenantId)
      setFormData(DEFAULT_NEW_SCAN)
      setCurrentStep('basic')
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

  const handleClose = () => {
    clearNewScanDraft(tenantId)
    setRefused([])
    setFormData(DEFAULT_NEW_SCAN)
    setCurrentStep('basic')
    createdConfigIdRef.current = null
    onOpenChange(false)
  }

  const renderStep = () => {
    switch (currentStep) {
      case 'basic':
        return <BasicInfoStep data={formData} onChange={handleDataChange} />
      case 'targets':
        return (
          <>
            {refused.length > 0 && <ScopeRefusalPanel refused={refused} className="mx-4 mt-4" />}
            <TargetsStep data={formData} onChange={handleDataChange} />
          </>
        )
      case 'options':
        return <OptionsStep data={formData} onChange={handleDataChange} showProfile />
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

  const isLoading = isSubmitting || isCreating

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('scans.new.title')}</DialogTitle>
          <DialogDescription>{t('scans.new.description')}</DialogDescription>
          <ScanStepper
            className="px-0 pt-2 pb-0 sm:px-0"
            currentStep={currentStep}
            onStepClick={handleStepClick}
            steps={STEPS}
          />
        </DialogHeader>

        <DialogBody className="px-0 py-0 sm:px-0">{renderStep()}</DialogBody>

        <DialogFooter className="sm:items-center sm:justify-between">
          <div className="flex flex-col items-center gap-1 sm:flex-row sm:justify-start">
            {isLastStep && awaitingApproval && (
              <p
                className="text-xs text-muted-foreground sm:order-2 sm:max-w-[18rem]"
                data-testid="scope-wait-notice"
              >
                {t('scans.new.waitNotice')}
              </p>
            )}
            {isLastStep && !blocked && approvalLack && (
              <p className="text-xs text-destructive sm:order-2 sm:max-w-[16rem]">{approvalLack}</p>
            )}
            {isLastStep && blocked && !awaitingApproval && (
              <p
                id="review-blocked"
                className="text-xs text-destructive sm:order-2 sm:max-w-[16rem]"
              >
                {review.blockers[0]}
              </p>
            )}
            {!isFirstStep && (
              <Button
                type="button"
                variant="ghost"
                onClick={handleBack}
                disabled={isLoading}
                className="w-full sm:w-auto"
              >
                <ChevronLeft className="me-1 h-4 w-4" />
                {t('scans.common.back')}
              </Button>
            )}
          </div>

          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <Button
              type="button"
              variant="outline"
              onClick={handleClose}
              disabled={isLoading}
              className="w-full sm:w-auto order-2 sm:order-1"
            >
              {t('common.cancel')}
            </Button>

            {isLastStep && awaitingApproval ? (
              <Button
                type="button"
                onClick={() => void handleSubmit({ waitForScope: true })}
                disabled={isLoading || waitBlocked}
                title={waitBlocked ? review.blockers[0] : undefined}
                className="order-1 h-auto w-full whitespace-normal py-2 sm:order-2 sm:w-auto"
              >
                {isLoading ? (
                  <Loader2 className="me-2 h-4 w-4 shrink-0 animate-spin" />
                ) : (
                  <Clock className="me-2 h-4 w-4 shrink-0" />
                )}
                {t('scans.new.createWhenApproved')}
              </Button>
            ) : isLastStep ? (
              <Button
                type="button"
                onClick={() => void handleSubmit()}
                disabled={isLoading || blocked || !!approvalLack}
                title={blocked ? review.blockers[0] : approvalLack || undefined}
                aria-describedby={blocked ? 'review-blocked' : undefined}
                className="w-full sm:w-auto order-1 sm:order-2"
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
            ) : (
              <Button
                type="button"
                onClick={handleNext}
                className="w-full sm:w-auto order-1 sm:order-2"
              >
                {t('scans.common.next')}
                <ChevronRight className="ms-1 h-4 w-4" />
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
