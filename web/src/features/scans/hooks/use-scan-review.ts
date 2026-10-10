'use client'

/**
 * Everything the Review step shows and the reasons Start is disabled, from
 * the server's answers only: the scope check of the direct targets (the same
 * request the selection summary made, so it is cached), the workflow preview
 * (readiness, blocking steps, an active freeze window) and the form's own
 * completeness. The create request is re-validated by the API anyway.
 */

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useScopeCheck } from '@/features/scope'
import { useDebounce } from '@/hooks/use-debounce'
import type { NewScanFormData } from '../types'
import { basicInfoError, directTargets, scheduleError, targetsError } from '../lib/scan-form'
import {
  useWorkflowPreview,
  type WorkflowPreviewRequest,
} from '../components/new-scan/workflow-preview'
import { SUMMARY_SCOPE_DEBOUNCE_MS } from '../components/target-picker/selection-summary'

export interface ScanReview {
  /** Why the scan cannot be created as it is; empty when it can. */
  blockers: string[]
  /** What the user should know before starting. */
  warnings: string[]
  /** Direct targets the scope check refused (by name). */
  refused: string[]
  scope: ReturnType<typeof useScopeCheck>
  workflow: ReturnType<typeof useWorkflowPreview>
  targets: string[]
}

export function useScanReview(
  form: NewScanFormData,
  workflowRequest: WorkflowPreviewRequest,
  enabled: boolean
): ScanReview {
  const { t } = useTranslation()
  const targets = directTargets(form)
  const joined = useDebounce(targets.join('\n'), SUMMARY_SCOPE_DEBOUNCE_MS)
  const list = enabled && joined ? joined.split('\n') : []
  const scope = useScopeCheck(list, {
    sensor_preference:
      form.sensorPreference === 'tenant' || form.sensorPreference === 'platform'
        ? form.sensorPreference
        : 'auto',
    scanner_name: form.mode === 'single' ? form.scannerName || undefined : undefined,
  })
  const workflow = useWorkflowPreview(workflowRequest, enabled && form.mode === 'workflow')

  return useMemo(() => {
    const blockers: string[] = []
    const warnings: string[] = []
    for (const problem of [
      basicInfoError(form, t),
      targetsError(form, t),
      scheduleError(form, { requireFuture: true }, t),
    ]) {
      if (problem) blockers.push(problem)
    }
    const refused = (scope.results ?? []).filter((r) => !r.allowed).map((r) => r.target ?? '')
    if (refused.length > 0) {
      // Create refuses the whole request when a direct target is refused.
      blockers.push(
        t(
          refused.length === 1 ? 'scans.review.blockedOne' : 'scans.review.blockedMany',
          undefined,
          { count: refused.length }
        )
      )
    }
    const wf = workflow.data
    if (wf?.blocking) {
      const reasons = (wf.nodes ?? [])
        .map((n) => n.blocking?.message)
        .filter((m): m is string => !!m)
      const why = reasons[0] ?? wf.targets?.error?.message
      blockers.push(
        why
          ? t('scans.review.workflowWouldNotStartWhy', undefined, { why })
          : t('scans.review.workflowWouldNotStart')
      )
    }
    if (wf?.freeze) {
      warnings.push(
        t('scans.review.freeze', undefined, {
          window: wf.freeze.window ?? '',
          until: wf.freeze.until
            ? t('scans.review.freezeUntil', undefined, {
                time: new Date(wf.freeze.until).toLocaleString(),
              })
            : '',
        })
      )
    }
    if (form.targets.assetGroupIds.length > 0) {
      warnings.push(t('scans.review.groupsResolved'))
    }
    if (scope.error) {
      warnings.push(t('scans.scope.unavailable'))
    }
    return { blockers, warnings, refused, scope, workflow, targets }
  }, [form, scope, workflow, targets, t])
}
