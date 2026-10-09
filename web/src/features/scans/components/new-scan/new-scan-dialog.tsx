/**
 * New Scan Dialog
 *
 * Multi-step wizard dialog for creating new scans.
 * Connects to the scan configuration API to create and optionally trigger scans.
 */

'use client'

import { useMemo, useState, useRef } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { ChevronLeft, ChevronRight, Loader2, Play } from 'lucide-react'
import { ScanRoutingSection, toZonePreviewRequest, triggerErrorHint } from '@/features/scan-zones'
import { WorkflowPreviewSection } from './workflow-preview'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import { ScanStepper, type ScanWizardStep } from './scan-stepper'
import { BasicInfoStep } from './basic-info-step'
import { TargetsStep } from './targets-step'
import { OptionsStep } from './options-step'
import { ScheduleStep } from './schedule-step'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../types'
import { basicInfoError, formDataToCreateRequest, targetsError } from '../../lib/scan-form'
import { getErrorMessage } from '@/lib/api/error-handler'
import { notifyScannerConfigWarnings } from '../../lib/scanner-config-warnings'
import { useCreateScanConfig, invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import { useTranslation } from '@/context/i18n-provider'
import {
  refusedFromError,
  scopeRefusalSummary,
  ScopeRefusalPanel,
  type ScopeRefusal,
} from '@/features/scope'

interface NewScanDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSubmit?: (data: NewScanFormData) => void
}

const STEPS: ScanWizardStep[] = ['basic', 'targets', 'options', 'schedule']

export function NewScanDialog({ open, onOpenChange, onSubmit }: NewScanDialogProps) {
  const [currentStep, setCurrentStep] = useState<ScanWizardStep>('basic')
  const [formData, setFormData] = useState<NewScanFormData>(DEFAULT_NEW_SCAN)
  const [isSubmitting, setIsSubmitting] = useState(false)
  // Targets the server refused on create (TARGET_OUT_OF_SCOPE details).
  const [refused, setRefused] = useState<ScopeRefusal[]>([])
  const { t } = useTranslation()

  // Store created scan config ID for triggering
  const createdConfigIdRef = useRef<string | null>(null)

  // API hooks
  const { trigger: createScanConfig, isMutating: isCreating } = useCreateScanConfig()

  // Scan zones (RFC-023): the picker and routing preview appear once the
  // team has zones and the user may read them.
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const { data: zonesData } = useScanZones(canReadZones && open)
  const zones = useMemo(() => zonesData?.data ?? [], [zonesData?.data])
  const previewRequest = useMemo(
    () => toZonePreviewRequest(formDataToCreateRequest(formData), formData.scanZoneId),
    [formData]
  )

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
        const problem = basicInfoError(formData)
        if (problem) {
          toast.error(problem)
          return false
        }
        return true
      }
      case 'targets': {
        const problem = targetsError(formData)
        if (problem) {
          toast.error(problem)
          return false
        }
        return true
      }
      case 'options':
        return true
      case 'schedule':
        return true
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

  const handleSubmit = async () => {
    if (!validateCurrentStep()) return

    const targetProblem = targetsError(formData)
    if (targetProblem) {
      toast.error(targetProblem)
      setCurrentStep('targets')
      return
    }

    setIsSubmitting(true)
    try {
      // Map form data to API request format
      const request = formDataToCreateRequest(formData)

      // Validate the mapped request has targets
      // This can happen if asset IDs couldn't be resolved to names
      const requestHasAssetGroups = request.asset_group_ids && request.asset_group_ids.length > 0
      const requestHasTargets = request.targets && request.targets.length > 0
      if (!requestHasAssetGroups && !requestHasTargets) {
        toast.error('Unable to resolve selected assets. Please try selecting them again.')
        return
      }

      // Create the scan configuration
      const scanConfig = await createScanConfig(request)

      if (!scanConfig) {
        throw new Error('Failed to create scan configuration')
      }
      notifyScannerConfigWarnings(scanConfig)

      createdConfigIdRef.current = scanConfig.id

      // Trigger scan immediately if requested
      if (formData.schedule.runImmediately) {
        // Import trigger function dynamically to avoid hook rules issue
        const { post } = await import('@/lib/api/client')
        const { scanEndpoints } = await import('@/lib/api/endpoints')

        try {
          await post(scanEndpoints.trigger(scanConfig.id), {})
          toast.success(`Scan "${formData.name}" started successfully`)
        } catch (triggerError) {
          // Scan config was created but trigger failed - show specific error
          const triggerRefused = refusedFromError(triggerError)
          const triggerErrorMsg =
            triggerRefused.length > 0
              ? scopeRefusalSummary(t, triggerRefused)
              : getErrorMessage(triggerError, 'Unknown error')
          console.error('Failed to trigger scan:', triggerError)

          // Show a persistent error toast with action buttons
          toast.error(
            `Scan "${formData.name}" was created but failed to start: ${triggerErrorMsg}`,
            {
              duration: 10000, // Keep visible for 10 seconds
              action: {
                label: 'View Scan',
                onClick: () => {
                  // Navigate to the scan detail page
                  window.location.href = `/scans/${scanConfig.id}`
                },
              },
              description:
                triggerErrorHint(triggerError) ??
                'You can manually trigger the scan from the scan details page.',
            }
          )

          // Still close dialog and refresh - the scan was created successfully
          await invalidateScanConfigsCache()
          onSubmit?.(formData)
          setFormData(DEFAULT_NEW_SCAN)
          setCurrentStep('basic')
          createdConfigIdRef.current = null
          onOpenChange(false)
          return
        }
      } else {
        toast.success(`Scan "${formData.name}" scheduled successfully`)
      }

      // Invalidate caches to refresh lists
      await invalidateScanConfigsCache()

      // Call optional callback
      onSubmit?.(formData)

      // Reset and close
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
      toast.error(getErrorMessage(error, 'Failed to create scan. Please try again.'))
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleClose = () => {
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
        return <OptionsStep data={formData} onChange={handleDataChange} />
      case 'schedule':
        return (
          <>
            <ScheduleStep data={formData} onChange={handleDataChange} />
            {formData.mode === 'workflow' && formData.workflowId && (
              <WorkflowPreviewSection
                request={{
                  scan_workflow_id: formData.workflowId,
                  targets: previewRequest.targets,
                  asset_group_ids: previewRequest.asset_group_ids,
                  scan_zone_id: formData.scanZoneId ?? undefined,
                }}
              />
            )}
            {canReadZones && zones.length > 0 && (
              <ScanRoutingSection
                zones={zones}
                value={formData.scanZoneId}
                onChange={(scanZoneId) => handleDataChange({ scanZoneId })}
                request={previewRequest}
              />
            )}
          </>
        )
      default:
        return null
    }
  }

  const isLoading = isSubmitting || isCreating

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-h-[90vh] overflow-hidden p-0 w-full sm:max-w-[600px]">
        <DialogHeader className="border-b px-6 py-4">
          <DialogTitle>New Scan</DialogTitle>
          <DialogDescription>Configure and launch a new security scan</DialogDescription>
        </DialogHeader>

        {/* Stepper */}
        <div className="min-w-0 border-b">
          <ScanStepper currentStep={currentStep} onStepClick={handleStepClick} />
        </div>

        {/* Step Content */}
        <div className="max-h-[50vh] overflow-y-auto overflow-x-hidden">{renderStep()}</div>

        {/* Footer */}
        <div className="flex flex-col-reverse gap-3 border-t px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <div className="flex justify-center sm:justify-start">
            {!isFirstStep && (
              <Button
                type="button"
                variant="ghost"
                onClick={handleBack}
                disabled={isLoading}
                className="w-full sm:w-auto"
              >
                <ChevronLeft className="me-1 h-4 w-4" />
                Back
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
              Cancel
            </Button>

            {isLastStep ? (
              <Button
                type="button"
                onClick={handleSubmit}
                disabled={isLoading}
                className="w-full sm:w-auto order-1 sm:order-2"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="me-2 h-4 w-4 animate-spin" />
                    {formData.schedule.runImmediately ? 'Starting...' : 'Scheduling...'}
                  </>
                ) : (
                  <>
                    <Play className="me-2 h-4 w-4" />
                    {formData.schedule.runImmediately ? 'Start Scan' : 'Schedule Scan'}
                  </>
                )}
              </Button>
            ) : (
              <Button
                type="button"
                onClick={handleNext}
                className="w-full sm:w-auto order-1 sm:order-2"
              >
                Next
                <ChevronRight className="ms-1 h-4 w-4" />
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
