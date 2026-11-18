import { useTranslation } from '@/context/i18n-provider'
import { humanizeIdentifier } from '@/lib/humanize-identifier'

type Translate = ReturnType<typeof useTranslation>['t']

// A key the catalogs do not have returns this fallback unchanged.
const MISSING = '\u0000'

/**
 * "organization.idp_create" -> "Identity provider added" (key
 * admin.auditAction.<code>). A code the catalogs do not know (a newer
 * server) reads as its words, never as the raw code.
 */
export function auditActionLabel(t: Translate, action: string): string {
  const label = t(`admin.auditAction.${action}`, MISSING)
  if (label !== MISSING) return label
  const [area, verb] = action.split('.')
  return humanizeIdentifier(verb ?? area)
}

/** `auditActionLabel` bound to the active language. */
export function useAuditActionLabel(): (action: string) => string {
  const { t } = useTranslation()
  return (action) => auditActionLabel(t, action)
}
