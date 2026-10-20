/**
 * Edit Scan Dialog
 *
 * Multi-step wizard dialog for editing an existing scan configuration.
 * Reuses the same step components as NewScanDialog with pre-populated data.
 */

'use client'

import { useState, useEffect, useMemo } from 'react'
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { ChevronLeft, ChevronRight, Loader2, Save } from 'lucide-react'

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
import { notifyScannerConfigWarnings } from '../lib/scanner-config-warnings'
import { useUpdateScanConfig, invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import type { ScanConfig } from '@/lib/api/scan-types'
import { refusedFromError, ScopeRefusalPanel, type ScopeRefusal } from '@/features/scope'

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
        },
        formData.scanZoneId
      ),
    [formData]
  )

  const { trigger: updateScanConfig, isMutating: isUpdating } = useUpdateScanConfig(
    scanConfig?.id ?? ''
  )

  // Pre-populate form when scanConfig changes
  useEffect(() => {
    if (scanConfig && open) {
      setFormData(scanConfigToFormData(scanConfig))
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

  const handleClose = () => {
    setRefused([])
    setCurrentStep('basic')
    onOpenChange(false)
  }

  const renderStep = () => {
    switch (currentStep) {
      case 'basic':
        return <BasicInfoStep data={formData} onChange={handleDataChange} lockMode />
      case 'targets':
        return (
          <div>
            {refused.length > 0 && <ScopeRefusalPanel refused={refused} className="mx-6 mt-4" />}
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

  const isLoading = isSubmitting || isUpdating

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('scans.edit.title')}</DialogTitle>
          <DialogDescription>
            {t('scans.edit.description', undefined, { name: scanConfig?.name ?? '' })}
          </DialogDescription>
          <ScanStepper
            className="px-0 pt-2 pb-0 sm:px-0"
            currentStep={currentStep}
            onStepClick={handleStepClick}
          />
        </DialogHeader>

        <DialogBody className="px-0 py-0 sm:px-0">{renderStep()}</DialogBody>

        <DialogFooter className="sm:items-center sm:justify-between">
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
