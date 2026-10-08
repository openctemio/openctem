/**
 * Lifetimes offered when creating an `oct_` API key (API keys page and the
 * MCP connection key). Every key expires: the API requires
 * `expires_in_days` between 1 and 365, so there is no "never" choice.
 */
export const API_KEY_EXPIRY_OPTIONS = [
  { value: '30', label: '30 days' },
  { value: '90', label: '90 days' },
  { value: '365', label: '1 year' },
] as const

export const DEFAULT_API_KEY_EXPIRY_DAYS = '90'
