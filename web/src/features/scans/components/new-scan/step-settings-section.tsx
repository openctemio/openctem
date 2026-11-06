'use client'

/**
 * Step settings (Options step): for each step of the chosen workflow that
 * has standard params, the value the workflow runs with at the scan's depth
 * and a switch to set this scan's own value. The override is saved as the
 * scan's step_params (one entry per step key); the workflow itself is never
 * changed, so it works on system workflows too. The fields are the workflow
 * editor's (ParamField): one component for a capability param everywhere.
 */

import { useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useScanWorkflow } from '@/lib/api/scan-workflow-hooks'
import type { ScanStepParams } from '@/lib/api/scan-types'
import { ParamField } from '@/features/scan-workflows/components/param-field'
import {
  capabilityForStep,
  type CapabilityParam,
} from '@/features/scan-workflows/lib/capability-graph'
import { useCapabilityTable } from '@/features/scan-workflows/lib/use-capability-table'
import { withParam } from '@/features/scan-workflows/lib/step-settings'
import { useWorkflowPreview, type WorkflowPreviewRequest } from './workflow-preview'

/** The capabilities that offer step settings, and the params of each. */
export const STEP_SETTINGS_PARAMS: Record<string, string[]> = {
  'vuln.templates': ['severity', 'tags', 'exclude_tags'],
}

interface Props {
  workflowId: string
  request: WorkflowPreviewRequest
  value: ScanStepParams
  onChange: (value: ScanStepParams) => void
}

export function StepSettingsSection({ workflowId, request, value, onChange }: Props) {
  const { t } = useTranslation()
  const { data: workflow } = useScanWorkflow(workflowId, { revalidateOnFocus: false })
  const { table } = useCapabilityTable()
  const preview = useWorkflowPreview(request)
  // Switches that are on; a step with a stored entry starts on.
  const [on, setOn] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(Object.keys(value).map((k) => [k, true]))
  )

  const rows = useMemo(() => {
    const out: {
      key: string
      name: string
      params: CapabilityParam[]
      shown: Record<string, unknown>
    }[] = []
    for (const step of workflow?.steps ?? []) {
      const cap = capabilityForStep(table, step)
      const names = cap ? STEP_SETTINGS_PARAMS[cap.key] : undefined
      if (!cap || !names) continue
      const node = preview.data?.nodes?.find((n) => n.step_key === step.step_key)
      out.push({
        key: step.step_key,
        name: step.name || step.step_key,
        params: cap.params.filter((p) => names.includes(p.name)),
        // The workflow's value at the scan's depth: the step's config, then
        // the depth's params over it.
        shown: { ...(step.config ?? {}), ...(node?.depth_params ?? {}) },
      })
    }
    return out
  }, [workflow, table, preview.data])

  if (rows.length === 0) return null

  const setEntry = (key: string, entry: Record<string, unknown> | undefined) => {
    const next = { ...value }
    if (entry && Object.keys(entry).length > 0) next[key] = entry
    else delete next[key]
    onChange(next)
  }

  return (
    <fieldset className="space-y-3" data-testid="step-settings">
      <legend className="text-sm font-medium">{t('scans.stepSettings.title')}</legend>
      <p className="text-muted-foreground text-xs">{t('scans.stepSettings.help')}</p>
      {rows.map((row) => {
        const enabled = on[row.key] === true
        const current = enabled ? { ...row.shown, ...(value[row.key] ?? {}) } : row.shown
        const switchId = `step-override-${row.key}`
        return (
          <div key={row.key} className="space-y-3 rounded-md border p-3">
            <div className="flex items-center justify-between gap-3">
              <Label htmlFor={switchId} className="text-sm font-medium">
                {row.name}
                <span className="text-muted-foreground block text-xs font-normal">
                  {enabled ? t('scans.stepSettings.custom') : t('scans.stepSettings.workflowValue')}
                </span>
              </Label>
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground text-xs">
                  {t('scans.stepSettings.override')}
                </span>
                <Switch
                  id={switchId}
                  checked={enabled}
                  onCheckedChange={(c) => {
                    setOn((prev) => ({ ...prev, [row.key]: c }))
                    if (c) {
                      // Start from what the workflow runs with.
                      const seed: Record<string, unknown> = {}
                      for (const p of row.params) {
                        if (row.shown[p.name] !== undefined) seed[p.name] = row.shown[p.name]
                      }
                      setEntry(row.key, seed)
                    } else {
                      setEntry(row.key, undefined)
                    }
                  }}
                />
              </div>
            </div>
            <div className="space-y-3">
              {row.params.map((p) => (
                <ParamField
                  // Remount when the switch or the shown value changes: the
                  // text fields keep their own draft.
                  key={`${row.key}-${p.name}-${enabled}-${JSON.stringify(current[p.name] ?? null)}`}
                  param={p}
                  value={current[p.name]}
                  readOnly={!enabled}
                  onChange={(v) => setEntry(row.key, withParam(value[row.key], p.name, v))}
                />
              ))}
            </div>
          </div>
        )
      })}
    </fieldset>
  )
}
