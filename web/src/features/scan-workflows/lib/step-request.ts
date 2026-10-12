/**
 * One workflow step as a save request entry, shared by the form and the
 * builder. The API replaces a whole step on save, so every field the step
 * has is sent: a field left out is reset (this is how retries, conditions
 * and tool preferences used to be lost on edit).
 */

import type { CreateStepRequest, ScanWorkflowStep, UIPosition } from '@/lib/api'
import { isTempStepId } from '@/lib/utils'

/**
 * A canvas position as whole numbers: the canvas works in fractional (and
 * negative) coordinates, the stored layout in whole ones.
 */
export function roundPosition(p: UIPosition | undefined): UIPosition | undefined {
  if (!p || !Number.isFinite(p.x) || !Number.isFinite(p.y)) return undefined
  return { x: Math.round(p.x), y: Math.round(p.y) }
}

export function toStepRequest(s: ScanWorkflowStep, idx: number): CreateStepRequest {
  const pinned = !!s.tool && s.tool.trim() !== ''
  const pos = roundPosition(s.ui_position)
  return {
    // A saved step keeps its id, so the save updates it in place and its run
    // history stays attached. A new step carries a temporary id only.
    ...(isTempStepId(s.id) ? {} : { id: s.id }),
    step_key: s.step_key,
    name: s.name,
    description: s.description || undefined,
    order: idx + 1,
    tool: pinned ? s.tool : '',
    // The capability the step runs (a catalog key or the tool's own words).
    // Empty for a pinned tool lets the API take the tool's declared words.
    capabilities: s.capabilities ?? [],
    prefer_tools: pinned ? [] : (s.prefer_tools ?? []),
    timeout_seconds: s.timeout_seconds,
    depends_on: s.depends_on ?? [],
    max_retries: s.max_retries ?? 0,
    retry_delay_seconds: s.retry_delay_seconds ?? 0,
    ...(s.condition ? { condition: s.condition } : {}),
    ...(pos ? { ui_position: pos } : {}),
    ...(s.config ? { config: s.config } : {}),
  }
}
