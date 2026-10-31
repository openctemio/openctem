/**
 * Lifetimes offered when creating an `oct_` API key (API keys page, service
 * accounts and the MCP connection key). Every key expires: the API requires
 * `expires_in_days` between 1 and the organization's maximum (default 90
 * days, never above the platform ceiling of 365), so there is no "never"
 * choice and nothing above the maximum is offered.
 */
export const API_KEY_EXPIRY_OPTIONS = [
  { value: '7', label: '7 days', labelKey: 'settings.apiKeys.expiry.d7' },
  { value: '30', label: '30 days', labelKey: 'settings.apiKeys.expiry.d30' },
  { value: '90', label: '90 days', labelKey: 'settings.apiKeys.expiry.d90' },
  { value: '180', label: '180 days', labelKey: 'settings.apiKeys.expiry.d180' },
  { value: '365', label: '1 year', labelKey: 'settings.apiKeys.expiry.d365' },
] as const

export const DEFAULT_API_KEY_EXPIRY_DAYS = '90'

/** The platform ceiling of a key's lifetime, in days. */
export const API_KEY_LIFETIME_CEILING_DAYS = 365

export interface ExpiryOption {
  value: string
  label: string
  labelKey: string
  /** Set for the organization's own maximum when it is not a standard choice. */
  days?: number
}

/**
 * The choices allowed under the organization's maximum: the standard ones at
 * or below it, plus the maximum itself when it is not one of them. The
 * default is 90 days, or the maximum when that is lower.
 */
export function expiryOptionsFor(maxDays: number | undefined): {
  options: ExpiryOption[]
  defaultValue: string
} {
  const max =
    maxDays && maxDays >= 1
      ? Math.min(Math.floor(maxDays), API_KEY_LIFETIME_CEILING_DAYS)
      : API_KEY_LIFETIME_CEILING_DAYS
  const options: ExpiryOption[] = API_KEY_EXPIRY_OPTIONS.filter((o) => Number(o.value) <= max).map(
    (o) => ({ ...o })
  )
  if (!options.some((o) => Number(o.value) === max)) {
    options.push({
      value: String(max),
      label: `${max} days`,
      labelKey: 'settings.apiKeys.expiry.days',
      days: max,
    })
    options.sort((a, b) => Number(a.value) - Number(b.value))
  }
  const defaultValue = String(Math.min(Number(DEFAULT_API_KEY_EXPIRY_DAYS), max))
  return { options, defaultValue }
}
