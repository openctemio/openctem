/**
 * Integration Types
 *
 * Types for managing external integrations and connections.
 * Integrations are pull-based data sources that the platform connects to.
 */

/**
 * Integration category
 */
export type IntegrationCategory =
  | 'scm' // Source Code Management: GitHub, GitLab, Bitbucket
  | 'security' // Security Tools: Tenable, DefectDojo
  | 'ticketing' // Issue Trackers: Jira
  | 'cloud' // declared by the API, no client yet; not offered
  | 'notification' // Notifications: Slack, Teams, Email

/**
 * Integration provider
 */
export type IntegrationProvider =
  // SCM
  | 'github'
  | 'gitlab'
  | 'bitbucket'
  | 'azure_devops'
  | 'codecommit'
  | 'local'
  // Security
  | 'wiz'
  | 'snyk'
  | 'tenable'
  | 'crowdstrike'
  | 'jira'
  | 'linear'
  | 'asana'
  // Cloud
  | 'aws'
  | 'gcp'
  | 'azure'
  // Notification
  | 'slack'
  | 'teams'
  | 'telegram'
  | 'email'
  | 'webhook'
  | 'splunk'

/**
 * Integration status
 */
export type IntegrationStatus =
  'connected' | 'disconnected' | 'error' | 'pending' | 'expired' | 'disabled'

/**
 * Authentication type
 */
export type AuthType = 'oauth' | 'token' | 'api_key' | 'basic' | 'app'

/**
 * SCM Extension - additional fields specific to SCM integrations
 */
export interface SCMExtension {
  scm_organization?: string
  repository_count: number
  webhook_id?: string
  webhook_url?: string
  default_branch_pattern?: string
  auto_import_repos: boolean
  import_private_repos: boolean
  import_archived_repos: boolean
  include_patterns?: string[]
  exclude_patterns?: string[]
  last_repo_sync_at?: string
}

/**
 * Severity levels for notification filtering
 */
export type NotificationSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none'

/**
 * All known severity levels for notification filtering
 */
export const ALL_NOTIFICATION_SEVERITIES: {
  value: NotificationSeverity
  label: string
  color: string
}[] = [
  { value: 'critical', label: 'Critical', color: 'bg-red-500' },
  { value: 'high', label: 'High', color: 'bg-orange-500' },
  { value: 'medium', label: 'Medium', color: 'bg-yellow-500' },
  { value: 'low', label: 'Low', color: 'bg-blue-500' },
  { value: 'info', label: 'Info', color: 'bg-gray-500' },
  { value: 'none', label: 'None', color: 'bg-gray-300' },
]

/**
 * Default enabled severities for new notification channels
 */
export const DEFAULT_ENABLED_SEVERITIES: NotificationSeverity[] = ['critical', 'high']

/**
 * Notification event type identifier, e.g. `sla_breach`, `new_finding`.
 *
 * Intentionally a bare string. The authoritative catalog — which identifiers
 * exist, their labels, descriptions, categories, which module each requires and
 * which are on by default — is served by `GET /api/v1/me/event-types` and read
 * through `useTenantEventTypes()`.
 *
 * This used to be a 16-value union with a matching `ALL_NOTIFICATION_EVENT_TYPES`
 * array, `EVENT_CATEGORY_LABELS` map and a client-side module filter, all
 * maintained by hand against `integration.AllEventTypes()` in the api. They
 * drifted: six event types the backend routes had no checkbox here, so no
 * operator could enable them, and two event categories had no label. Narrowing
 * this back to a union would reintroduce that — a value the server sends would
 * fail to typecheck here for no reason other than that this file had not caught
 * up.
 */
export type NotificationEventType = string

/**
 * Event category identifier, e.g. `finding`, `approval`.
 *
 * A bare string for the same reason as {@link NotificationEventType}: the
 * category list and its display labels come from the API.
 */
export type NotificationEventCategory = string

/**
 * Notification Extension - additional fields specific to notification integrations
 */
export interface NotificationExtension {
  channel_id?: string
  channel_name?: string
  enabled_severities: NotificationSeverity[] // Dynamic severity filtering
  enabled_event_types: string[] // Dynamic event type IDs (database-driven)
  message_template?: string
  include_details: boolean
  min_interval_minutes: number
}

/**
 * Integration entity
 */
export interface Integration {
  id: string
  tenant_id?: string
  name: string
  description?: string
  provider: IntegrationProvider
  category: IntegrationCategory
  status: IntegrationStatus
  status_message?: string
  /**
   * False when the backend has no client for this provider (e.g. a Linear or
   * Asana row created before the API began refusing them). Such an
   * integration never runs; show it as not supported.
   */
  supported?: boolean

  // Connection details
  auth_type: AuthType
  base_url?: string
  credentials_masked?: string // e.g., "ghp_xxxx...xxxx"

  // Sync info
  last_sync_at?: string
  next_sync_at?: string
  sync_interval_minutes?: number
  sync_error?: string

  // Statistics
  stats?: {
    total_assets: number
    total_findings: number
    total_repositories?: number
  }

  // Metadata
  config?: Record<string, unknown>
  metadata?: Record<string, unknown>

  // SCM-specific extension (only present for SCM integrations)
  scm_extension?: SCMExtension

  // Notification-specific extension (only present for notification integrations)
  notification_extension?: NotificationExtension

  // Timestamps
  created_at: string
  updated_at: string
  created_by?: string
}

/**
 * Integration list filters
 */
export interface IntegrationListFilters {
  category?: IntegrationCategory
  provider?: IntegrationProvider
  status?: IntegrationStatus
  search?: string
  page?: number
  per_page?: number
  sort?: string
  order?: 'asc' | 'desc'
}

/**
 * Create integration request
 */
export interface CreateIntegrationRequest {
  name: string
  description?: string
  category: IntegrationCategory
  provider: IntegrationProvider
  auth_type: AuthType
  base_url?: string
  credentials?: string
  scm_organization?: string
  /** Non-sensitive provider settings (e.g. Tenable execution_mode/engine). */
  config?: Record<string, unknown>
}

/**
 * Update integration request
 */
export interface UpdateIntegrationRequest {
  name?: string
  description?: string
  credentials?: string
  base_url?: string
  scm_organization?: string
  /** Non-sensitive provider settings (e.g. Tenable execution_mode/engine). */
  config?: Record<string, unknown>
}

/**
 * Create notification integration request
 */
export interface CreateNotificationIntegrationRequest {
  name: string
  description?: string
  provider: 'slack' | 'teams' | 'telegram' | 'webhook' | 'email' | 'splunk'
  auth_type: AuthType
  credentials: string
  channel_id?: string
  channel_name?: string
  enabled_severities?: NotificationSeverity[] // Severity levels to notify on
  enabled_event_types?: string[] // Event type IDs (database-driven)
  message_template?: string
  include_details?: boolean
  min_interval_minutes?: number
  // Non-sensitive provider config (e.g. Splunk HEC hec_url / index / sourcetype).
  metadata?: Record<string, unknown>
}

/**
 * Test notification response
 */
export interface TestNotificationResponse {
  success: boolean
  message_id?: string
  error?: string
}

/**
 * Test credentials request
 */
export interface TestCredentialsRequest {
  category: IntegrationCategory
  provider: IntegrationProvider
  base_url?: string
  auth_type: AuthType
  credentials: string
  scm_organization?: string
}

/**
 * Test credentials response
 */
export interface TestCredentialsResponse {
  success: boolean
  message: string
  repository_count?: number
  organization?: string
  username?: string
}

/**
 * SCM Repository from provider
 */
export interface SCMRepository {
  id: string
  name: string
  full_name: string
  description?: string
  html_url: string
  clone_url: string
  ssh_url: string
  default_branch: string
  is_private: boolean
  is_fork: boolean
  is_archived: boolean
  language?: string
  languages?: Record<string, number>
  topics?: string[]
  stars: number
  forks: number
  size: number
  created_at: string
  updated_at: string
  pushed_at: string
}

/**
 * List SCM repositories response
 */
export interface ListSCMRepositoriesResponse {
  repositories: SCMRepository[]
  total: number
  has_more: boolean
  next_page: number
}

/**
 * Provider configuration
 */
export interface ProviderConfig {
  id: IntegrationProvider
  name: string
  category: IntegrationCategory
  description: string
  icon: string
  authTypes: AuthType[]
  features: string[]
  docUrl: string
  available: boolean
}

/**
 * Provider configurations
 */
/**
 * Only providers the backend has a working client for are listed. Rows for other
 * declared providers can still arrive from the API; nothing here renders them.
 */
export const INTEGRATION_PROVIDERS: Partial<Record<IntegrationProvider, ProviderConfig>> = {
  // SCM Providers
  github: {
    id: 'github',
    name: 'GitHub',
    category: 'scm',
    description: 'Connect to GitHub repositories for code scanning',
    icon: 'github',
    authTypes: ['oauth', 'token', 'app'],
    features: ['repositories', 'code_scanning', 'webhooks'],
    docUrl: 'https://docs.github.com',
    available: true,
  },
  gitlab: {
    id: 'gitlab',
    name: 'GitLab',
    category: 'scm',
    description: 'Connect to GitLab projects for code scanning',
    icon: 'gitlab',
    authTypes: ['oauth', 'token'],
    features: ['repositories', 'code_scanning', 'webhooks'],
    docUrl: 'https://docs.gitlab.com',
    available: true,
  },
  bitbucket: {
    id: 'bitbucket',
    name: 'Bitbucket',
    category: 'scm',
    description: 'Connect to Bitbucket repositories for code scanning',
    icon: 'bitbucket',
    authTypes: ['oauth', 'token', 'app'],
    features: ['repositories', 'code_scanning', 'webhooks'],
    docUrl: 'https://developer.atlassian.com/bitbucket',
    available: true,
  },
  azure_devops: {
    id: 'azure_devops',
    name: 'Azure DevOps',
    category: 'scm',
    description: 'Connect to Azure Repos for code scanning',
    icon: 'azure',
    authTypes: ['oauth', 'token'],
    features: ['repositories', 'code_scanning', 'pipelines'],
    docUrl: 'https://docs.microsoft.com/azure/devops',
    available: true,
  },

  tenable: {
    id: 'tenable',
    name: 'Tenable',
    category: 'security',
    description: 'Import vulnerability scan results from Tenable',
    icon: 'tenable',
    authTypes: ['api_key'],
    features: ['findings', 'assets', 'compliance'],
    docUrl: 'https://docs.tenable.com',
    available: false,
  },

  jira: {
    id: 'jira',
    name: 'Jira',
    category: 'ticketing',
    description: 'Create and sync issues with Jira',
    icon: 'jira',
    authTypes: ['oauth', 'token', 'basic'],
    features: ['issues', 'webhooks', 'sync'],
    docUrl: 'https://developer.atlassian.com/cloud/jira',
    available: false,
  },

  // Notifications
  slack: {
    id: 'slack',
    name: 'Slack',
    category: 'notification',
    description: 'Send notifications to Slack channels',
    icon: 'slack',
    authTypes: ['oauth', 'token'],
    features: ['notifications', 'alerts', 'commands'],
    docUrl: 'https://api.slack.com',
    available: true,
  },
  teams: {
    id: 'teams',
    name: 'Microsoft Teams',
    category: 'notification',
    description: 'Send notifications to Teams channels',
    icon: 'teams',
    authTypes: ['oauth', 'token'],
    features: ['notifications', 'alerts'],
    docUrl: 'https://docs.microsoft.com/microsoftteams',
    available: true,
  },
  telegram: {
    id: 'telegram',
    name: 'Telegram',
    category: 'notification',
    description: 'Send notifications to Telegram chats',
    icon: 'telegram',
    authTypes: ['token'],
    features: ['notifications', 'alerts'],
    docUrl: 'https://core.telegram.org/bots/api',
    available: true,
  },
  email: {
    id: 'email',
    name: 'Email',
    category: 'notification',
    description: 'Send email notifications',
    icon: 'email',
    authTypes: ['basic', 'api_key'],
    features: ['notifications', 'reports'],
    docUrl: '',
    available: false,
  },
  webhook: {
    id: 'webhook',
    name: 'Webhook',
    category: 'notification',
    description: 'Send notifications to custom webhooks',
    icon: 'webhook',
    authTypes: ['token', 'basic'],
    features: ['notifications', 'events'],
    docUrl: '',
    available: true,
  },
  splunk: {
    id: 'splunk',
    name: 'Splunk',
    category: 'notification',
    description: 'Forward findings and events to Splunk via HTTP Event Collector',
    icon: 'splunk',
    authTypes: ['token'],
    features: ['siem', 'notifications', 'events'],
    docUrl: 'https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector',
    available: true,
  },
}

/**
 * Category configuration
 */
export const INTEGRATION_CATEGORIES: Partial<
  Record<
    IntegrationCategory,
    {
      label: string
      description: string
      icon: string
    }
  >
> = {
  scm: {
    label: 'Source Control',
    description: 'Connect to code repositories',
    icon: 'git-branch',
  },
  security: {
    label: 'Security Tools',
    description: 'Import security findings',
    icon: 'shield',
  },
  ticketing: {
    label: 'Issue Tracking',
    description: 'Create and sync issues',
    icon: 'ticket',
  },
  notification: {
    label: 'Notifications',
    description: 'Send alerts and notifications',
    icon: 'bell',
  },
}

// =============================================================================
// Notification Events (audit trail)
// =============================================================================

/**
 * Notification event status (final processing status)
 */
export type NotificationEventStatus = 'completed' | 'failed' | 'skipped'

/**
 * Send result for a single integration
 */
export interface NotificationEventSendResult {
  integration_id: string
  name: string
  provider: string
  status: 'success' | 'failed'
  message_id?: string
  error?: string
  sent_at: string
}

/**
 * Notification event entry (from notification_events table)
 */
export interface NotificationEventEntry {
  id: string
  event_type: string
  aggregate_type?: string
  aggregate_id?: string
  title: string
  body?: string
  severity: string
  url?: string
  status: NotificationEventStatus
  integrations_total: number
  integrations_matched: number
  integrations_succeeded: number
  integrations_failed: number
  send_results: NotificationEventSendResult[]
  last_error?: string
  retry_count: number
  created_at: string
  processed_at: string
}

/**
 * Notification events response with pagination
 */
export interface NotificationEventsResponse {
  data: NotificationEventEntry[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/**
 * Status configuration
 */
export const INTEGRATION_STATUS_CONFIG: Record<
  IntegrationStatus,
  {
    label: string
    color: string
    bgColor: string
  }
> = {
  connected: {
    label: 'Connected',
    color: 'text-green-500',
    bgColor: 'bg-green-500',
  },
  disconnected: {
    label: 'Disconnected',
    color: 'text-gray-500',
    bgColor: 'bg-gray-500',
  },
  error: {
    label: 'Error',
    color: 'text-red-500',
    bgColor: 'bg-red-500',
  },
  pending: {
    label: 'Pending',
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-500',
  },
  expired: {
    label: 'Expired',
    color: 'text-orange-500',
    bgColor: 'bg-orange-500',
  },
  disabled: {
    label: 'Disabled',
    color: 'text-gray-400',
    bgColor: 'bg-gray-400',
  },
}
