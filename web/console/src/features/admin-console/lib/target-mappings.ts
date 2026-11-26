/**
 * Target mappings: which asset types a scanner can scan, keyed by the target
 * types it declares in `supported_targets`. Smart filtering uses the active
 * mappings at scan time to skip assets the scanner cannot handle. The accepted
 * target and asset types are the API's (`useTargetMappingTypes`); only the
 * numeric bounds below are mirrored here.
 */

import { useTranslation } from '@/context/i18n-provider'
import { humanizeIdentifier } from '@/lib/humanize-identifier'
import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'

/** Priority of a primary mapping (`is_primary` is derived from it). */
export const PRIMARY_PRIORITY = 10
/** Priority the API gives a new mapping when none is set. */
export const DEFAULT_PRIORITY = 100
/** Bounds the API enforces on `priority`. */
export const MIN_PRIORITY = 1
export const MAX_PRIORITY = 1000
/** The API's limit on `description`. */
export const MAX_DESCRIPTION_LENGTH = 500

/**
 * Words for a target type. The accepted values come from the API
 * (`GET /admin/target-mappings/types`); the labels and hints are catalog
 * entries `admin.targetType.<value>.label` and `.hint`. A value the catalog
 * does not know (a newer API) shows as its humanized name.
 */
export function useTargetTypeText() {
  const { t } = useTranslation()
  return {
    label: (value: string) => t(`admin.targetType.${value}.label`, humanizeIdentifier(value)),
    hint: (value: string) => t(`admin.targetType.${value}.hint`, ''),
    /** An asset type's name in the console language (the tenant app's own catalog). */
    asset: (value: string) => t(`assets.typeLabel.${value}`, getAssetTypeLabel(value)),
  }
}

/** The i18n translate function, or the English fallback itself when none is given. */
type Translate = (key: string, fallback: string, vars?: Record<string, string | number>) => string
const english: Translate = (_key, fallback, vars) => {
  const plural = /^\{(\w+), plural, one \{(.*)\} other \{(.*)\}\}$/.exec(fallback)
  const text = plural ? (Number(vars?.[plural[1]]) === 1 ? plural[2] : plural[3]) : fallback
  return text.replace(/\{(\w+)\}|#/g, (m, k) => {
    if (m === '#') return plural ? String(vars?.[plural[1]] ?? m) : m
    return String(vars?.[k] ?? m)
  })
}

export interface TargetMappingFormValues {
  priority: string
  description: string
}

/**
 * Client-side copy of the API's rules, so the dialog can say what is wrong
 * before a round trip. The API stays the authority.
 */
export function validateTargetMappingForm(
  v: TargetMappingFormValues,
  t: Translate = english
): {
  priority?: string
  description?: string
} {
  const errors: { priority?: string; description?: string } = {}
  const trimmed = v.priority.trim()
  const n = Number(trimmed)
  if (trimmed === '' || !Number.isInteger(n)) {
    errors.priority = t('admin.targetMappingDialog.priorityWhole', 'Enter a whole number')
  } else if (n < MIN_PRIORITY || n > MAX_PRIORITY) {
    errors.priority = t('admin.targetMappingDialog.priorityRange', 'Between {min} and {max}', {
      min: MIN_PRIORITY,
      max: MAX_PRIORITY,
    })
  }
  if (v.description.trim().length > MAX_DESCRIPTION_LENGTH) {
    errors.description = t(
      'admin.targetMappingDialog.descriptionMax',
      '{max, plural, one {At most # character} other {At most # characters}}',
      {
        max: MAX_DESCRIPTION_LENGTH,
      }
    )
  }
  return errors
}
