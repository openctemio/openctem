/**
 * Edit Scan Dialog
 *
 * Edits a saved scan in the same wizard shell as New scan (scan-wizard.tsx):
 * the same steps, free navigation, live summary and validity gate. Save is
 * offered on every step (an edit usually changes one thing) and with
 * Ctrl/Cmd+Enter. The form is filled when the dialog opens, never again while
 * it is open: a run finishing refetches the scan, and that must not wipe what
 * is being typed. Design: research/418.
 */

'use client'

import { useState, useEffect, useMemo, useRef } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { ScanRoutingSection, toZonePreviewRequest } from '@/features/scan-zones'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { useAssetGroups } from '@/features/asset-groups'
import { Permission, useHasPermission } from '@/lib/permissions'
import { useScanWorkflow } from '@/lib/api/scan-workflow-hooks'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { Loader2, Save } from 'lucide-react'

import { type ScanWizardStep } from './new-scan/scan-stepper'
import { ScanWizard, useWizardSteps } from './new-scan/scan-wizard'
import { ScanSummaryContent, summaryLine } from './new-scan/scan-summary'
import { BasicInfoStep } from './new-scan/basic-info-step'
import { TargetsStep } from './new-scan/targets-step'
import { OptionsStep } from './new-scan/options-step'
import { ScheduleStep } from './new-scan/schedule-step'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../types'
import { formDataToUpdateRequest, scanConfigToFormData } from '../lib/scan-form'
import { issueCount, scanStepIssues } from '../lib/wizard-validity'
import { getErrorMessage } from '@/lib/api/error-handler'
import { apiTargetOptions } from '../lib/dynamic-targets'
import { notifyScannerConfigWarnings } from '../lib/scanner-config-warnings'
import { useUpdateScanConfig, invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import type { ScanConfig } from '@/lib/api/scan-types'
import { refusedFromError, ScopeRefusalPanel, type ScopeRefusal } from '@/features/scope'
import { useTargetsCheck } from '../hooks/use-targets-check'
import { useWorkflowReadiness } from '../hooks/use-workflow-readiness'
import { isFormDirty } from '../lib/form-dirty'
import { useDiscardPrompt } from './new-scan/wizard-chrome'

interface EditScanDialogProps {
  scanConfig: ScanConfig | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
}

const STEPS: ScanWizardStep[] = ['basic', 'targets', 'options', 'schedule']

export function EditScanDialog({ scanConfig, open, onOpenChange, onSuccess }: EditScanDialogProps) {
  const { t } = useTranslation()
  const nav = useWizardSteps('basic')
  const currentStep = nav.step
  const setCurrentStep = nav.setStep
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

  const { trigger: updateScanConfig, isMutating: isUpdating } = useUpdateScanConfig(
    scanConfig?.id ?? ''
  )

  // Fill the form when the dialog opens (or opens on another scan); keep
  // what it loaded with, to ask before closing with changes.
  const initial = useRef<NewScanFormData>(DEFAULT_NEW_SCAN)
  const loadedFor = useRef<string | null>(null)
  const restartNav = nav.reset
  useEffect(() => {
    if (!open) {
      loadedFor.current = null
      return
    }
    if (!scanConfig || loadedFor.current === scanConfig.id) return
    loadedFor.current = scanConfig.id
    const loaded = scanConfigToFormData(scanConfig)
    initial.current = loaded
    setFormData(loaded)
    restartNav()
  }, [scanConfig, open, restartNav])

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

  // Targets the server refused on save (TARGET_OUT_OF_SCOPE details).
  const [refused, setRefused] = useState<ScopeRefusal[]>([])

  const handleDataChange = (data: Partial<NewScanFormData>) => {
    setFormData((prev) => ({ ...prev, ...data }))
  }

  // The same check the Targets step shows (one cached request).
  const { check, readiness, sent } = useTargetsCheck(formData, open)
  // An edit may send back a one-off run that has already happened.
  const workflowReadiness = useWorkflowReadiness(formData, open)
  const issues = useMemo(
    () => scanStepIssues(formData, { readiness, requireFuture: false, t }),
    [formData, readiness, t]
  )
  const canSave = issueCount(issues, STEPS) === 0

  const { data: chosenWorkflow } = useScanWorkflow(
    formData.mode === 'workflow' && formData.workflowId ? formData.workflowId : null,
    { revalidateOnFocus: false }
  )
  const whatLabel =
    formData.mode === 'workflow'
      ? (chosenWorkflow?.name ?? t('scans.new.workflowFallback'))
      : formData.scannerName || t('scans.new.scannerFallback')

  const handleSubmit = async () => {
    nav.setAttempted(true)
    if (!canSave || !scanConfig) return

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
    nav.reset()
    onOpenChange(false)
  }
  const { requestClose, prompt: discardPrompt } = useDiscardPrompt(
    () => isFormDirty(formData, initial.current),
    close
  )

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
        return (
          <OptionsStep
            data={formData}
            onChange={handleDataChange}
            workflowRequest={workflowRequest}
          />
        )
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

  const results = check.results ?? []
  const refusedCount = results.filter((r) => !r.allowed).length
  const summaryFacts = {
    data: formData,
    whatLabel,
    directCount: sent.length,
    ready: check.results ? results.length - refusedCount : undefined,
    blocked: check.results ? refusedCount : undefined,
    checking: check.available && check.isLoading && !check.results,
    workflowReadiness,
    issues,
    steps: STEPS,
    shownSteps: nav.attempted ? new Set(STEPS) : nav.seen,
    onGo: setCurrentStep,
  }

  return (
    <ScanWizard
      open={open}
      onRequestClose={requestClose}
      title={
        scanConfig?.name
          ? t('scans.edit.titleNamed', undefined, { name: scanConfig.name })
          : t('scans.edit.title')
      }
      description={t('scans.edit.description', undefined, { name: scanConfig?.name ?? '' })}
      steps={STEPS}
      step={currentStep}
      onStepChange={setCurrentStep}
      issues={issues}
      attempted={nav.attempted}
      seen={nav.seen}
      summary={<ScanSummaryContent {...summaryFacts} />}
      summaryLine={summaryLine(summaryFacts, t)}
      submitOnEveryStep
      canSubmit={canSave}
      onSubmit={() => void handleSubmit()}
      isLoading={isLoading}
      after={discardPrompt}
      primary={
        <Button
          type="button"
          onClick={() => void handleSubmit()}
          disabled={isLoading || !canSave}
          aria-describedby="wizard-note"
          aria-keyshortcuts="Control+Enter Meta+Enter"
          data-testid="wizard-save"
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
      }
    >
      {renderStep()}
    </ScanWizard>
  )
}
