/**
 * A capability node's tool selection and standard settings, as the
 * inspector edits them. The API validates every save
 * (stage.ValidateParams); these helpers only keep the form honest: the form
 * offers the contract's params only, so an unknown key cannot be entered.
 */

import type { ScanWorkflowStep } from '@/lib/api'
import type { Capability, CapabilityParam } from './capability-graph'

export type ToolSelection = 'auto' | 'prefer' | 'pin'

/** How a step picks its tool, as the API derives it. */
export function selectionOf(step: Pick<ScanWorkflowStep, 'tool' | 'prefer_tools'>): ToolSelection {
  if (step.tool && step.tool.trim() !== '') return 'pin'
  if (step.prefer_tools && step.prefer_tools.length > 0) return 'prefer'
  return 'auto'
}

/**
 * The step after a selection change. The capability is kept as the step's
 * capability word, so an auto or prefer step still names what it runs.
 * Leaving pin drops the pinned tool's own settings (x.<tool> and plain
 * keys): they would reach other tools.
 */
export function withSelection(
  step: ScanWorkflowStep,
  capability: Capability,
  mode: ToolSelection,
  tools: string[]
): ScanWorkflowStep {
  const base = {
    ...step,
    capabilities: [capability.key],
    config: mode === 'pin' ? step.config : standardOnly(step.config, capability),
  }
  if (mode === 'pin') {
    const tool = tools[0] ?? capability.defaultTool
    return { ...base, tool, prefer_tools: [] }
  }
  if (mode === 'prefer') {
    const prefer = tools.filter((t) => capability.tools.includes(t))
    return { ...base, tool: '', prefer_tools: prefer }
  }
  return { ...base, tool: '', prefer_tools: [] }
}

/** Keeps only the capability's standard params (and executor keys). */
export function standardOnly(
  config: Record<string, unknown> | undefined,
  capability: Capability
): Record<string, unknown> | undefined {
  if (!config) return config
  const names = new Set(capability.params.map((p) => p.name))
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(config)) {
    if (names.has(k) || k === 'exclude') out[k] = v
  }
  return out
}

/**
 * The value to store for a param from a form input, or undefined to clear
 * it. Returns an error message for a value the contract refuses.
 */
export function paramValue(
  param: CapabilityParam,
  raw: string | boolean | string[]
): { value: unknown; error?: string } {
  switch (param.type) {
    case 'boolean':
      return { value: raw === true }
    case 'integer': {
      const text = String(raw).trim()
      if (text === '') return { value: undefined }
      const n = Number(text)
      if (!Number.isInteger(n)) return { value: undefined, error: 'Enter a whole number.' }
      if (param.min !== undefined && n < param.min)
        return { value: undefined, error: `At least ${param.min}.` }
      if (param.max !== undefined && n > param.max)
        return { value: undefined, error: `At most ${param.max}.` }
      return { value: n }
    }
    case 'port_list': {
      const text = String(raw).replace(/\s+/g, '')
      if (text === '') return { value: undefined }
      if (!/^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$/.test(text))
        return { value: undefined, error: 'Ports and ranges, such as 80,443,8000-8100.' }
      return { value: text }
    }
    case 'string_list': {
      const list = Array.isArray(raw)
        ? raw
        : String(raw)
            .split(',')
            .map((v) => v.trim())
            .filter(Boolean)
      if (list.length === 0) return { value: undefined }
      const bad = param.enum.length > 0 ? list.find((v) => !param.enum.includes(v)) : undefined
      if (bad) return { value: undefined, error: `${bad} is not allowed.` }
      return { value: list }
    }
    default: {
      const text = String(raw).trim()
      if (text === '') return { value: undefined }
      if (param.enum.length > 0 && !param.enum.includes(text))
        return { value: undefined, error: `${text} is not allowed.` }
      return { value: text }
    }
  }
}

/** The config with one param set (or removed when value is undefined). */
export function withParam(
  config: Record<string, unknown> | undefined,
  name: string,
  value: unknown
): Record<string, unknown> {
  const out = { ...(config ?? {}) }
  if (value === undefined) delete out[name]
  else out[name] = value
  return out
}

/** Tools that do not take a set standard param (they cannot run the node). */
export function toolsMissingParams(
  capability: Capability,
  config: Record<string, unknown> | undefined
): Record<string, string[]> {
  const set = capability.params.map((p) => p.name).filter((n) => config && n in config)
  const out: Record<string, string[]> = {}
  for (const tool of capability.tools) {
    const mapping = capability.toolParams[tool] ?? {}
    const missing = set.filter((n) => !(n in mapping))
    if (missing.length > 0) out[tool] = missing
  }
  return out
}
