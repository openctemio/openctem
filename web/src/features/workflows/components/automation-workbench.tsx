'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Edge, OnEdgesChange, OnNodesChange } from '@xyflow/react'
import { X } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { useWorkflow, useWorkflowCatalog, useWorkflowTrace } from '@/lib/api/workflow-hooks'
import type {
  Workflow,
  WorkflowPreviewResponse,
  WorkflowValidateResponse,
} from '@/lib/api/workflow-types'
import { Permission, useHasPermission } from '@/lib/permissions'
import { toApiGraph, type AutomationNode } from '../lib/automation-graph'
import { countsFromSteps } from '../lib/automation-lifecycle'
import { AutomationCanvas } from './automation-canvas'
import { AutomationLifecycleBar, GoLiveChecks } from './automation-lifecycle-bar'
import { DeliveriesList, ValidationPanel } from './automation-trace-panels'

/**
 * The automation builder: lifecycle header (simulate or live, versions,
 * validate, preview, go live), the canvas with counts on its steps, the
 * checks and "Before going live" panels, and what a preview would send.
 * A new automation (not saved yet) gets the canvas only.
 */
export function AutomationWorkbench({
  workflow,
  nodes,
  edges,
  setNodes,
  setEdges,
  onNodesChange,
  onEdgesChange,
}: {
  workflow: Workflow | null
  nodes: AutomationNode[]
  edges: Edge[]
  setNodes: (fn: (nds: AutomationNode[]) => AutomationNode[]) => void
  setEdges: (fn: (eds: Edge[]) => Edge[]) => void
  onNodesChange: OnNodesChange<AutomationNode>
  onEdgesChange: OnEdgesChange
}) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.AutomationsWrite)
  const { data: catalog, isLoading: catalogLoading } = useWorkflowCatalog()
  const { data: fresh } = useWorkflow(workflow?.id ?? null)
  const wf = fresh ?? workflow
  const [preview, setPreview] = useState<WorkflowPreviewResponse | null>(null)
  const [validation, setValidation] = useState<WorkflowValidateResponse | null>(null)
  const [focusRequest, setFocusRequest] = useState<{ nodeKey: string; seq: number } | null>(null)
  const { data: trace } = useWorkflowTrace(wf && !preview ? wf.id : null, 'simulate')

  const draft = useMemo(() => toApiGraph(nodes, edges), [nodes, edges])
  const getDraft = useCallback(() => draft, [draft])
  // The draft as last loaded or saved: the page hands a new automation object
  // on both, together with the canvas it loaded. Comparing the canvas with
  // that (not with the server's copy) keeps server-side normalisation from
  // reading as unsaved edits.
  const draftJson = useMemo(() => JSON.stringify(draft), [draft])
  const [baseline, setBaseline] = useState<string | null>(null)
  // The latest draft, read (not subscribed to) when an automation loads: only
  // a newly loaded or saved automation resets the baseline, not every edit.
  const draftJsonRef = useRef(draftJson)
  useEffect(() => {
    draftJsonRef.current = draftJson
  }, [draftJson])
  useEffect(() => {
    setBaseline(workflow ? draftJsonRef.current : null)
  }, [workflow])
  const dirty = baseline !== null && baseline !== draftJson

  const counts = useMemo(() => {
    if (preview) return countsFromSteps(preview.steps)
    if (trace && trace.runs > 0) return countsFromSteps(trace.steps)
    return null
  }, [preview, trace])

  const nodeName = useCallback(
    (key: string) => nodes.find((n) => n.data.nodeKey === key)?.data.label,
    [nodes]
  )

  const mode = wf?.mode ?? 'simulate'

  return (
    <>
      {wf && (
        <AutomationLifecycleBar
          workflow={wf}
          dirty={dirty}
          getDraft={getDraft}
          validation={validation}
          onPreview={setPreview}
          onValidate={setValidation}
        />
      )}
      {wf && mode === 'simulate' && (
        <p className="border-t px-4 py-2 text-xs text-muted-foreground" role="status">
          {counts && !preview && trace
            ? t(
                'automations.simulate.bannerTrace',
                'Simulate. Counts from {runs} recorded runs in the last {days} days. Nothing is changed or sent.',
                { runs: trace.runs, days: trace.days }
              )
            : t('automations.simulate.banner', 'Simulate. Nothing is changed or sent.')}
        </p>
      )}
      <AutomationCanvas
        nodes={nodes}
        edges={edges}
        setNodes={setNodes}
        setEdges={setEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        catalog={catalog}
        catalogLoading={catalogLoading}
        readOnly={!canWrite}
        counts={counts}
        focusRequest={focusRequest}
        sidePanel={
          wf ? (
            <>
              {validation && (
                <ValidationPanel
                  result={validation}
                  nodeName={nodeName}
                  onSelect={(nodeKey) =>
                    setFocusRequest((r) => ({ nodeKey, seq: (r?.seq ?? 0) + 1 }))
                  }
                />
              )}
              {(mode === 'simulate' || wf.draft_changed) && (
                <section className="rounded-lg border p-3" data-testid="before-going-live">
                  <h3 className="mb-2 text-sm font-semibold">
                    {t('automations.golive.title', 'Before going live')}
                  </h3>
                  <GoLiveChecks workflow={wf} validation={validation} dirty={dirty} />
                </section>
              )}
            </>
          ) : null
        }
      />
      {preview && (
        <section className="space-y-3 border-t p-4" data-testid="preview-result">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-semibold">
              {t('automations.preview.title', 'Preview of {n} recent subjects', {
                n: preview.subjects,
              })}
            </h3>
            <Button variant="ghost" size="sm" onClick={() => setPreview(null)}>
              <X className="h-4 w-4" />
              {t('automations.preview.clear', 'Clear preview')}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            {t(
              'automations.preview.hint',
              'Counts on the steps come from this preview. Only subjects you may see are used; nothing is stored, changed or sent.'
            )}
          </p>
          <h4 className="text-sm font-medium">
            {t('automations.preview.wouldSend', 'Would send {n}', {
              n: preview.deliveries?.length ?? 0,
            })}
          </h4>
          <DeliveriesList deliveries={preview.deliveries ?? []} mode="simulate" />
        </section>
      )}
    </>
  )
}
