/**
 * Scan intensity (RFC-071): the probe ceiling a scan's runs may reach.
 *
 * The tiers below mirror the API's scan-stage catalog
 * (api/pkg/domain/stage): the API is the authority (it refuses a scanner or
 * workflow step above the intensity, and never dispatches one); the wizard
 * uses them only to offer what fits. Anything not listed counts as active,
 * never passive, as on the server.
 */

import type { ScanIntensity } from '@/lib/api/scan-types'

/** 0 passive, 1 active, 2 intrusive. */
export type ProbeTier = 0 | 1 | 2

export const DEFAULT_INTENSITY: ScanIntensity = 'active'

const INTENSITY_TIER: Record<ScanIntensity, ProbeTier> = { passive: 0, active: 1, intrusive: 2 }

const PASSIVE_TOOLS = new Set([
  'subfinder',
  'dnsx',
  'betterleaks',
  'trufflehog',
  'gitleaks',
  'semgrep',
  'codeql',
  'trivy',
  'osv-scanner',
  'grype',
  'checkov',
  'kics',
])
const INTRUSIVE_TOOLS = new Set(['zap'])

const PASSIVE_CAPABILITIES = new Set([
  'discover.subdomains',
  'subdomain',
  'resolve.dns',
  'dns',
  'secrets.code',
  'secrets',
  'sast.code',
  'sast',
  'sca.deps',
  'sca',
  'iac.misconfig',
  'iac',
  'container.image',
  'container',
])
const INTRUSIVE_CAPABILITIES = new Set(['dast.web'])

/** Step settings that point a DNS tool at resolvers of the user's choosing. */
const RESOLVER_KEYS = new Set([
  'resolver',
  'resolvers',
  'r',
  'rl',
  'resolver_list',
  'resolvers_file',
])

/** The highest tier the intensity allows. */
export function intensityTier(intensity: ScanIntensity | undefined): ProbeTier {
  return intensity ? INTENSITY_TIER[intensity] : 1
}

/** The lowest intensity that allows tier. */
export function intensityForTier(tier: ProbeTier): ScanIntensity {
  return tier === 0 ? 'passive' : tier === 1 ? 'active' : 'intrusive'
}

/** The tier a scanner probes at. */
export function toolTier(tool: string | undefined): ProbeTier {
  const name = (tool ?? '').trim().toLowerCase()
  if (INTRUSIVE_TOOLS.has(name)) return 2
  if (PASSIVE_TOOLS.has(name)) return 0
  return 1
}

function capabilitiesTier(capabilities: string[] | undefined): ProbeTier | undefined {
  const caps = (capabilities ?? []).map((c) => c.trim().toLowerCase()).filter(Boolean)
  if (caps.some((c) => INTRUSIVE_CAPABILITIES.has(c))) return 2
  const known = caps.filter((c) => PASSIVE_CAPABILITIES.has(c))
  if (known.length > 0 && known.length === caps.length) return 0
  return caps.length > 0 ? 1 : undefined
}

function hasCustomResolvers(config: Record<string, unknown> | undefined): boolean {
  return Object.entries(config ?? {}).some(([k, v]) => {
    if (!RESOLVER_KEYS.has(k.toLowerCase())) return false
    if (Array.isArray(v)) return v.length > 0
    if (typeof v === 'string') return v.trim() !== ''
    return v != null
  })
}

interface StepLike {
  tool?: string
  capabilities?: string[]
  config?: Record<string, unknown>
}

/** The tier a workflow step counts at against the scan's intensity. */
export function stepTier(step: StepLike): ProbeTier {
  const byTool = step.tool ? toolTier(step.tool) : undefined
  const byCaps = capabilitiesTier(step.capabilities)
  let tier: ProbeTier
  if (byTool === undefined && byCaps === undefined) tier = 1
  else tier = Math.max(byTool ?? 0, byCaps ?? 0) as ProbeTier
  const dns =
    (step.tool ?? '').toLowerCase() === 'dnsx' ||
    (step.capabilities ?? []).some((c) => ['resolve.dns', 'dns'].includes(c.toLowerCase()))
  if (tier === 0 && dns && hasCustomResolvers(step.config)) tier = 1
  return tier
}

/** The highest tier among a workflow's steps (active for an empty one). */
export function workflowTier(steps: StepLike[] | undefined): ProbeTier {
  if (!steps || steps.length === 0) return 1
  return steps.reduce<ProbeTier>((top, s) => Math.max(top, stepTier(s)) as ProbeTier, 0)
}

/** Whether a probe of tier fits under the intensity. */
export function fitsIntensity(tier: ProbeTier, intensity: ScanIntensity | undefined): boolean {
  return tier <= intensityTier(intensity)
}

/**
 * The tier the wizard's scope check asks at: a single check is checked at
 * its scanner's own tier (the API derives it from scanner_name); a workflow
 * at the scan's intensity, the most any of its steps may probe.
 */
export function scopeCheckTier(form: {
  mode: string
  intensity?: ScanIntensity
}): ProbeTier | undefined {
  return form.mode === 'workflow' ? intensityTier(form.intensity) : undefined
}
