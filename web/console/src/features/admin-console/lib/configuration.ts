import type { ConfigurationItem } from '../types'

/** Page order of the groups. */
export const CONFIG_GROUPS: ConfigurationItem['group'][] = [
  'instance',
  'sign_in',
  'email',
  'scanning',
  'storage',
  'ai',
  'console',
  'audit',
  'updates',
]

/** English group names (i18n fallback; keys admin.config.group.<group>). */
export const CONFIG_GROUP_LABELS: Record<ConfigurationItem['group'], string> = {
  instance: 'Instance',
  sign_in: 'Sign-up and sign-in',
  email: 'E-mail',
  scanning: 'Scanning',
  storage: 'Storage',
  ai: 'AI',
  console: 'Platform console',
  audit: 'Audit',
  updates: 'Software updates',
}

/** English setting names (i18n fallback; keys admin.config.item.<key>). */
export const CONFIG_ITEM_LABELS: Record<string, string> = {
  signup_policy: 'Sign-up policy',
  self_service_default_limits: 'Starting limits for self-service organizations',
  'email.smtp': 'Platform e-mail (SMTP)',
  legal: 'Legal pages and contacts',
  scan_approval_policy: 'Scan approval',
  platform_sensor_proof: 'Domain proof for platform scanning',
  shared_sensors: 'Shared sensors',
  console_mfa_policy: 'Security keys required for administrators',
  version_check: 'Daily version check',
  APP_URL: 'Public address',
  ADMIN_PUBLIC_URL: 'Console address',
  MANAGED_SERVICE: 'Managed service defaults',
  DEPLOYMENT_REGION: 'Deployment region',
  SIGNUP_MODE: 'Sign-up ceiling',
  CAPTCHA_TURNSTILE_SECRET: 'CAPTCHA (Turnstile) keys',
  SENSOR_PUBLIC_API_URL: 'Address sensors connect to',
  STORAGE_PROVIDER: 'Attachment storage',
  STORAGE_TENANT_QUOTA_MB: 'Storage quota per organization (MB)',
  AI_PLATFORM_PROVIDER: 'Platform AI provider',
  AI_PLATFORM_API_KEY: 'Platform AI key',
  ADMIN_ALLOWED_CIDRS: 'Networks allowed to reach the console',
  ADMIN_ELEVATION: 'Time-boxed elevation',
  OPENCTEM_PLANE: 'API plane',
  ADMIN_AUDIT_SINK: 'Admin audit stream',
  AUDIT_RETENTION_DAYS: 'Audit retention (days)',
  RATE_LIMIT_ENABLED: 'Request rate limits',
  LOG_LEVEL: 'Log level',
  VERSION_CHECK_ENABLED: 'Version check ceiling',
}

/** The i18n key of a setting name ("." is a key separator, so it becomes "_"). */
export function configItemKey(key: string): string {
  return `admin.config.item.${key.replace(/\./g, '_')}`
}

export type ConfigFilter = 'all' | 'console' | 'server' | 'restart' | 'planned'

export function filterConfig(items: ConfigurationItem[], f: ConfigFilter): ConfigurationItem[] {
  switch (f) {
    case 'console':
      return items.filter((i) => i.managed === 'console')
    case 'server':
      return items.filter((i) => i.managed === 'server')
    case 'restart':
      return items.filter((i) => i.restart_required)
    case 'planned':
      return items.filter((i) => i.planned)
    default:
      return items
  }
}
