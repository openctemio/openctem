/**
 * Edit Scan Dialog
 *
 * Multi-step wizard dialog for editing an existing scan configuration.
 * Reuses the same step components as NewScanDialog with pre-populated data.
 */

'use client'

import { useState, useEffect, useMemo, useRef } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { ScanRoutingSection, toZonePreviewRequest } from '@/features/scan-zones'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { useAssetGroups } from '@/features/asset-groups'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { ChevronRight, Loader2, Save } from 'lucide-react'

import { ScanStepper, type ScanWizardStep } from './new-scan/scan-stepper'
import { BasicInfoStep } from './new-scan/basic-info-step'
import { TargetsStep } from './new-scan/targets-step'
import { OptionsStep } from './new-scan/options-step'
import { ScheduleStep } from './new-scan/schedule-step'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../types'
import {
  basicInfoError,
  optionsError,
  formDataToUpdateRequest,
  scanConfigToFormData,
  targetsError,
  scheduleError,
} from '../lib/scan-form'
import { getErrorMessage } from '@/lib/api/error-handler'
import { apiTargetOptions } from '../lib/dynamic-targets'
import { notifyScannerConfigWarnings } from '../lib/scanner-config-warnings'
import { useUpdateScanConfig, invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import type { ScanConfig } from '@/lib/api/scan-types'
import { refusedFromError, ScopeRefusalPanel, type ScopeRefusal } from '@/features/scope'
import { useTargetsCheck } from '../hooks/use-targets-check'
import { targetsNextBlock } from '../lib/targets-step'
import { isFormDirty } from '../lib/form-dirty'
import { useDiscardPrompt, WizardFooter } from './new-scan/wizard-chrome'

interface EditScanDialogProps {
  scanConfig: ScanConfig | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
}

const STEPS: ScanWizardStep[] = ['basic', 'targets', 'options', 'schedule']

export function EditScanDialog({ scanConfig, open, onOpenChange, onSuccess }: EditScanDialogProps) {
  const { t } = useTranslation()
  const [currentStep, setCurrentStep] = useState<ScanWizardStep>('basic')
  const [formData, setFormData] = useState<NewScanFormData>(DEFAULT_NEW_SCAN)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Scan zones (RFC-023): same picker and preview as New scan.
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const { data: zonesData } = useScanZones(canReadZones && open)
  const zones = useMemo(() => zonesData?.data ?? [], [zonesData?.data])
  const previewRequest = useMemo(
    () =>
      toZonePreviewRequest(
        {
          targets: formData.targets.customTargets,
          asset_group_ids: formData.targets.assetGroupIds,
          scan_type: formData.mode === 'workflow' ? 'workflow' : 'single',
          scanner_name: formData.mode === 'single' ? formData.scannerName : undefined,
          scan_workflow_id: formData.mode === 'workflow' ? formData.workflowId : undefined,
          targets_per_job: formData.maxConcurrent || 10,
          target_options: apiTargetOptions(formData.targets.targetOptions),
        },
        formData.scanZoneId
      ),
    [formData]
  )

  const { trigger: updateScanConfig, isMutating: isUpdating } = useUpdateScanConfig(
    scanConfig?.id ?? ''
  )

  // Pre-populate form when scanConfig changes; keep what it loaded with, to
  // ask before closing with changes.
  const initial = useRef<NewScanFormData>(DEFAULT_NEW_SCAN)
  useEffect(() => {
    if (scanConfig && open) {
      const loaded = scanConfigToFormData(scanConfig)
      initial.current = loaded
      setFormData(loaded)
      setCurrentStep('basic')
    }
  }, [scanConfig, open])

  // The stored groups' names, for their chips on the Targets step.
  const hasGroups = (scanConfig?.asset_group_ids?.length ?? 0) > 0 || !!scanConfig?.asset_group_id
  const { data: groups } = useAssetGroups({
    filters: { per_page: 100, sort_by: 'name', sort_order: 'asc' },
    enabled: open && hasGroups,
  })
  useEffect(() => {
    if (groups.length === 0) return
    setFormData((prev) => {
      const names = { ...(prev.targets.assetGroupNames ?? {}) }
      let changed = false
      for (const g of groups) {
        if (prev.targets.assetGroupIds.includes(g.id) && !names[g.id]) {
          names[g.id] = g.name
          changed = true
        }
      }
      return changed ? { ...prev, targets: { ...prev.targets, assetGroupNames: names } } : prev
    })
  }, [groups])

  const currentStepIndex = STEPS.indexOf(currentStep)
  const isFirstStep = currentStepIndex === 0
  const isLastStep = currentStepIndex === STEPS.length - 1

  // Targets the server refused on save (TARGET_OUT_OF_SCOPE details).
  const [refused, setRefused] = useState<ScopeRefusal[]>([])

  const handleDataChange = (data: Partial<NewScanFormData>) => {
    setFormData((prev) => ({ ...prev, ...data }))
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
      case 'options': {
        const problem = optionsError(formData, t)
        if (problem) {
          toast.error(problem)
          return false
        }
        return true
      }
      case 'schedule': {
        const problem = scheduleError(formData, { requireFuture: false }, t)
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

  // Next on the Targets step waits while nothing can run (the same check the
  // step shows, one cached request).
  const { readiness } = useTargetsCheck(formData, open)
  const nextBlock = currentStep === 'targets' ? targetsNextBlock(readiness, t) : null

  const handleNext = () => {
    if (nextBlock) return
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
    if (!scanConfig) return

    setIsSubmitting(true)
    try {
      const request = formDataToUpdateRequest(formData, scanConfig, { canSetZone: canReadZones })
      const updated = await updateScanConfig(request)

      toast.success(t('scans.edit.updated', undefined, { name: formData.name }))
      notifyScannerConfigWarnings(updated, t)
      await invalidateScanConfigsCache()
      onSuccess?.()
      onOpenChange(false)
    } catch (error) {
      const scopeRefused = refusedFromError(error)
      if (scopeRefused.length > 0) {
        setRefused(scopeRefused)
        setCurrentStep('targets')
        return
      }
      console.error('Failed to update scan:', error)
      toast.error(getErrorMessage(error, t('scans.edit.updateFailed')))
    } finally {
      setIsSubmitting(false)
    }
  }

  const isLoading = isSubmitting || isUpdating

  const close = () => {
    setRefused([])
    setCurrentStep('basic')
    onOpenChange(false)
  }
  const { requestClose, prompt: discardPrompt } = useDiscardPrompt(
    () => isFormDirty(formData, initial.current),
    close
  )
  const handleOpenChange = (next: boolean) => {
    if (!next && !isLoading) requestClose()
  }

  const renderStep = () => {
    switch (currentStep) {
      case 'basic':
        return <BasicInfoStep data={formData} onChange={handleDataChange} lockMode />
      case 'targets':
        return (
          <div>
            {refused.length > 0 && (
              <ScopeRefusalPanel refused={refused} className="mx-4 mt-4 sm:mx-6" />
            )}
            <TargetsStep
              data={formData}
              onChange={handleDataChange}
              showCoverage={false}
              savedScan
            />
          </div>
        )
      case 'options':
        return <OptionsStep data={formData} onChange={handleDataChange} />
      case 'schedule':
        return (
          <>
            <ScheduleStep data={formData} onChange={handleDataChange} requireFutureRun={false} />
            {canReadZones && (
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

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent size="xl">
        <DialogHeader className="pb-0">
          <DialogTitle>
            {scanConfig?.name
              ? t('scans.edit.titleNamed', undefined, { name: scanConfig.name })
              : t('scans.edit.title')}
          </DialogTitle>
          <DialogDescription className="max-sm:sr-only">
            {t('scans.edit.description', undefined, { name: scanConfig?.name ?? '' })}
          </DialogDescription>
          <ScanStepper
            className="px-0 pt-1 pb-2 sm:px-0"
            currentStep={currentStep}
            onStepClick={handleStepClick}
          />
        </DialogHeader>

        <DialogBody className="px-0 py-0 sm:px-0">{renderStep()}</DialogBody>

        <WizardFooter
          onBack={isFirstStep ? undefined : handleBack}
          disabled={isLoading}
          note={nextBlock ?? undefined}
          noteId={nextBlock ? 'targets-next-blocked' : undefined}
          noteTone="destructive"
        >
          {isLastStep ? (
            <Button type="button" onClick={handleSubmit} disabled={isLoading}>
              {isLoading ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  {t('scans.common.saving')}
                </>
              ) : (
                <>
                  <Save className="me-2 h-4 w-4" />
                  {t('scans.edit.saveChanges')}
                </>
              )}
            </Button>
          ) : (
            <Button
              type="button"
              onClick={handleNext}
              disabled={!!nextBlock}
              aria-describedby={nextBlock ? 'targets-next-blocked' : undefined}
              data-testid="wizard-next"
            >
              {t('scans.common.next')}
              <ChevronRight className="ms-1 h-4 w-4" />
            </Button>
          )}
        </WizardFooter>
      </DialogContent>
      {discardPrompt}
    </Dialog>
  )
}
