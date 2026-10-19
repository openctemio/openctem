import type { TemplateType } from '@/lib/api/scanner-template-types'

/**
 * The scanner template type a template-driven scanner reads, or null when the
 * scanner takes no organization templates. The organization's own rules are
 * offered (and required for "Organization templates only") only for these.
 */
const TEMPLATE_TYPE_BY_SCANNER: Record<string, TemplateType> = {
  nuclei: 'nuclei',
  semgrep: 'semgrep',
  opengrep: 'semgrep',
  betterleaks: 'betterleaks',
  gitleaks: 'betterleaks',
}

export function templateTypeForScanner(scannerName: string | undefined): TemplateType | null {
  if (!scannerName) return null
  return TEMPLATE_TYPE_BY_SCANNER[scannerName.toLowerCase()] ?? null
}
