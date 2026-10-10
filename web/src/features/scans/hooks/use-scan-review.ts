'use client'

/**
 * Everything the Review step shows and the reasons Start is disabled, from
 * the server's answers only: the scope check of the direct targets (the same
 * request the selection summary made, so it is cached), the workflow preview
 * (readiness, blocking steps, targets waiting for their scan windows) and the form's own
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
  const { t } = useTranslation()

  return useMemo(() => {
    const blockers: string[] = []
    const warnings: string[] = []
    for (const problem of [
      basicInfoError(form),
      targetsError(form),
      scheduleError(form, { requireFuture: true }),
    ]) {
      if (problem) blockers.push(problem)
    }
    const refused = (scope.results ?? []).filter((r) => !r.allowed).map((r) => r.target ?? '')
    if (refused.length > 0) {
      // Create refuses the whole request when a direct target is refused.
      blockers.push(
        `${refused.length} ${refused.length === 1 ? 'target' : 'targets'} may not be scanned: remove ${refused.length === 1 ? 'it' : 'them'} or fix the scope first`
      )
    }
    const wf = workflow.data
    if (wf?.blocking) {
      const reasons = (wf.nodes ?? [])
        .map((n) => n.blocking?.message)
        .filter((m): m is string => !!m)
      const why = reasons[0] ?? wf.targets?.error?.message
      blockers.push(
        why ? `The workflow would not start: ${why}` : 'The workflow would not start as it is'
      )
    }
    const windows = wf?.targets?.windows
    if ((windows?.never_count ?? 0) > 0) {
      // The trigger refuses a run with a target whose windows never open.
      blockers.push(
        t(
          'scanWindows.review.never',
          '{n} targets have scan windows that never open: starting the scan is refused until a policy changes',
          { n: windows?.never_count ?? 0 }
        )
      )
    }
    if ((windows?.waiting_count ?? 0) > 0) {
      warnings.push(
        t(
          'scanWindows.review.waiting',
          '{n} targets wait for their scan windows; they are scanned when their windows open',
          { n: windows?.waiting_count ?? 0 }
        )
      )
    }
    if (form.targets.assetGroupIds.length > 0) {
      warnings.push(
        'Asset group members are resolved when the scan runs; members outside your scope are skipped then.'
      )
    }
    if (scope.error) {
      warnings.push(
        'The scope check is not available right now; the scan is still checked when it starts.'
      )
    }
    return { blockers, warnings, refused, scope, workflow, targets }
  }, [form, scope, workflow, targets, t])
}
