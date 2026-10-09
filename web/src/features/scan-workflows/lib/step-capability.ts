/**
 * Capability-first step editing, shared by the form and the builder: a step
 * names the capability it runs (a catalog key such as "resolve.dns") and
 * optionally prefers or pins a tool that implements it. A step can also be
 * started from a tool: its capability then comes from what the tool
 * implements (the one capability, or the user picks among several). Nothing
 * is hardcoded: a tool the catalog does not know keeps the words it
 * declares, and the API maps the two vocabularies.
 */

import type { ScanWorkflowStep } from '@/lib/api'
import type { Capability, CapabilityTable } from './capability-graph'

/** The capabilities a workflow step may run (not cross-cutting, routed). */
export function stepCapabilities(table: CapabilityTable): Capability[] {
  return table.capabilities.filter((c) => c.available && !c.crossCutting)
}

/** The capabilities a tool implements in the catalog. */
export function capabilitiesOfTool(table: CapabilityTable, tool: string): Capability[] {
  const t = tool.toLowerCase().trim()
  if (!t) return []
  return stepCapabilities(table).filter((c) => c.tools.includes(t))
}

/** The catalog capability a step names (by key), if any. */
export function namedCapability(
  table: CapabilityTable,
  step: Pick<ScanWorkflowStep, 'capabilities'>
): Capability | null {
  const words = (step.capabilities ?? []).map((c) => c.toLowerCase().trim())
  return stepCapabilities(table).find((c) => words.includes(c.key)) ?? null
}

/**
 * The step running a capability. A pinned tool that implements it stays
 * pinned; any other tool selection is reset to "any tool", because the
 * preferences were for the previous capability.
 */
export function withCapability(step: ScanWorkflowStep, cap: Capability): ScanWorkflowStep {
  const keepPin = !!step.tool && cap.tools.includes(step.tool)
  return {
    ...step,
    capabilities: [cap.key],
    tool: keepPin ? step.tool : '',
    prefer_tools: [],
  }
}

/**
 * The step started from a tool. One catalog capability: the step runs it
 * with the tool pinned. Several: the tool is pinned and `choose` lists the
 * capabilities to pick from (the step keeps a capability among them when it
 * already names one). None (a tool the catalog does not know): the step
 * keeps the tool's declared words.
 */
export function withTool(
  table: CapabilityTable,
  step: ScanWorkflowStep,
  tool: string,
  declared: string[]
): { step: ScanWorkflowStep; choose: Capability[] } {
  const caps = capabilitiesOfTool(table, tool)
  const base = { ...step, tool, prefer_tools: [] as string[] }
  if (caps.length === 1) return { step: { ...base, capabilities: [caps[0].key] }, choose: [] }
  if (caps.length > 1) {
    const current = namedCapability(table, step)
    const keep = current && caps.some((c) => c.key === current.key)
    return {
      step: { ...base, capabilities: keep ? [current.key] : [] },
      choose: keep ? [] : caps,
    }
  }
  return { step: { ...base, capabilities: [...declared] }, choose: [] }
}

/**
 * The capabilities a step in the old format can take: a step that names a
 * tool but not a catalog capability (its tool's old words, "recon,
 * subdomain"). Empty when the step is not in the old format or its tool
 * implements no catalog capability.
 */
export function legacyCapabilityFix(
  table: CapabilityTable,
  step: Pick<ScanWorkflowStep, 'tool' | 'capabilities'>
): Capability[] {
  const tool = (step.tool ?? '').trim()
  if (!tool || namedCapability(table, step)) return []
  return capabilitiesOfTool(table, tool)
}

/** The step in the new format: its capability named, its tool kept pinned. */
export function applyLegacyFix(step: ScanWorkflowStep, cap: Capability): ScanWorkflowStep {
  return { ...step, capabilities: [cap.key], prefer_tools: [] }
}
