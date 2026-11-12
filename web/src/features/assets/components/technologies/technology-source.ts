/**
 * The readable source of an asset technology: which kind of check saw it.
 * A template scan's detection (docs/architecture/template-facts.md) is a
 * secondary reading next to a fingerprinting probe, so the console names
 * the kind as well as the tool.
 */

type Translate = (key: string, fallback: string, params?: Record<string, string>) => string

const PROBE_TOOLS = new Set(['httpx', 'wappalyzer', 'webanalyze', 'whatweb'])
const TEMPLATE_TOOLS = new Set(['nuclei', 'zap'])

export function technologySourceLabel(source: string, t: Translate): string {
  const s = source.trim()
  const tool = s.toLowerCase()
  if (PROBE_TOOLS.has(tool)) {
    return t('assets.technologies.sourceKind.probe', 'HTTP probe ({tool})', { tool: s })
  }
  if (TEMPLATE_TOOLS.has(tool)) {
    return t('assets.technologies.sourceKind.templateScan', 'Template scan ({tool})', { tool: s })
  }
  if (tool === 'rules:organization') {
    return t(
      'assets.technologies.sourceKind.organizationRules',
      "Your organization's detection rules"
    )
  }
  if (tool.startsWith('rules:')) {
    return t('assets.technologies.sourceKind.platformRules', 'Detection rule pack {pack}', {
      pack: s.slice('rules:'.length),
    })
  }
  return s
}
