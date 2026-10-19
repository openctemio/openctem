/**
 * Settings navigation: the one source of truth for the settings rail, the
 * /settings landing page and the Settings section of the command palette (⌘K).
 *
 * Routes under /settings and /account (plus every item's own URL) render the
 * settings shell: the left sidebar swaps its content for this list, two levels
 * deep (group, then item), with a way back to the app. The main sidebar keeps a
 * single "Settings" link.
 *
 * Groups (research 178, 2026-10-18): My account, Organization (what the
 * organization is), Security (how it is protected and audited), Access (who and
 * what may sign in: people, teams, roles, tokens), Findings & assets (policies
 * on findings, risk and the inventory), Scanning (what scans may do and with
 * which tools), Scanner content (rules, templates and their sources),
 * Integrations. URLs never move with the grouping.
 *
 * Rules (src/config/__tests__/settings-nav.test.ts):
 * - every url has a page; no page is a scaffold;
 * - `permission` / `module` equal what the route guard enforces for the url,
 *   and personal items (/account) carry neither;
 * - a "Soon" badge if and only if the page is a ComingSoonPage;
 * - 2 to 9 items per group; titles in sentence case;
 * - every title, group, description and anchor has en and vi strings.
 *
 * Search (rail filter, /settings and ⌘K) matches titles, descriptions,
 * keywords and `anchors`: the settings inside a page, which link to
 * `<url>#<anchor id>` (src/config/settings-search.ts).
 */
import {
  GitMerge,
  Handshake,
  LifeBuoy,
  Globe,
  Activity,
  Bell,
  Bot,
  Boxes,
  Bug,
  Siren,
  Building,
  CalendarClock,
  Clock,
  Crosshair,
  DatabaseZap,
  FileBadge,
  FileCode2,
  FileSliders,
  FolderGit2,
  FolderKey,
  Gauge,
  GitBranch,
  History,
  Key,
  KeyRound,
  ListChecks,
  ArrowLeftRight,
  Lock,
  LockKeyhole,
  MessageSquare,
  Package,
  Puzzle,
  Scale,
  ClipboardCheck,
  ServerCog,
  Settings2,
  Shield,
  SlidersHorizontal,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  Timer,
  User,
  UserCog,
  Users,
  Wrench,
  Zap,
  type LucideIcon,
} from 'lucide-react'
import { Permission } from '@/lib/permissions'
import { matchesAllWords } from './settings-search'

/**
 * One setting inside a page, so search finds the setting and not only its page.
 * The page renders an element with this `id`; the search result links to
 * `<url>#<id>`, and the settings shell scrolls to it and highlights it.
 * i18n key: `settings.anchor.<item id>.<anchor id>`.
 */
export interface SettingsNavAnchor {
  id: string
  /** English title, sentence case. */
  title: string
  /** Extra words search matches on. */
  keywords?: string[]
}

export interface SettingsNavItem {
  /** Stable id. i18n keys: `settings.item.<id>` (title), `settings.desc.<id>`. */
  id: string
  /** English title, sentence case. */
  title: string
  /** One line: what this page configures. Shown on the landing page, searched by the filter. */
  description: string
  url: string
  icon: LucideIcon
  /** Permission the route guard requires. Omitted only for the user's own pages. */
  permission?: string
  /** Tenant module the route guard requires. */
  module?: string
  /** Sub-module of `module` that must be enabled (integration categories). */
  subModuleKey?: string
  /** 'Soon' when the page is a ComingSoonPage. */
  badge?: 'Soon'
  /** Extra words the rail filter and ⌘K match on. */
  keywords?: string[]
  /**
   * Listed only while a limit or a module deny applies to the organization
   * (GET /organization/limits says applies). Nothing applies by default.
   */
  onlyWhenLimitsApply?: boolean
  /** Settings on the page that search can find and link to directly. */
  anchors?: SettingsNavAnchor[]
}

export interface SettingsNavGroup {
  /** i18n key: `settings.group.<id>`. */
  id: string
  title: string
  items: SettingsNavItem[]
}

export const settingsNav: SettingsNavGroup[] = [
  {
    id: 'account',
    title: 'My account',
    items: [
      {
        id: 'profile',
        title: 'Profile',
        description: 'Your name, email and avatar.',
        url: '/account',
        icon: User,
        keywords: ['name', 'avatar', 'me'],
      },
      {
        id: 'account-security',
        title: 'Security',
        description: 'Password, two-factor authentication and active sessions.',
        url: '/account/security',
        icon: Shield,
        keywords: ['password', '2fa', 'mfa', 'totp', 'sessions'],
      },
      {
        id: 'preferences',
        title: 'Preferences',
        description: 'Theme, language, time zone and date format.',
        url: '/account/preferences',
        icon: Settings2,
        keywords: ['theme', 'dark mode', 'language', 'timezone'],
      },
      {
        id: 'my-notifications',
        title: 'Notifications',
        description: 'Which notifications you receive, and how.',
        url: '/account/notifications',
        icon: Bell,
        keywords: ['email', 'digest', 'alerts', 'mute'],
      },
      {
        id: 'activity',
        title: 'Activity',
        description: 'Your own recent sign-ins and actions.',
        url: '/account/activity',
        icon: Activity,
        keywords: ['history', 'sign-ins'],
      },
      {
        id: 'connected-apps',
        title: 'Connected applications',
        description: 'AI applications you allowed to read your data.',
        url: '/account/connected-apps',
        icon: Bot,
        keywords: ['mcp', 'oauth', 'ai', 'assistant', 'claude', 'disconnect'],
      },
    ],
  },
  {
    id: 'organization',
    title: 'Organization',
    items: [
      {
        id: 'org-general',
        title: 'General',
        description: 'Organization name, logo, file storage, ownership and deletion.',
        url: '/settings/general',
        icon: Building,
        permission: Permission.TeamUpdate,
        keywords: [
          'tenant',
          'branding',
          'logo',
          'timezone',
          'storage',
          's3',
          'delete organization',
          'transfer ownership',
        ],
        anchors: [
          {
            id: 'org-profile',
            title: 'Organization name and URL',
            keywords: ['name', 'slug', 'logo', 'website'],
          },
          {
            id: 'danger-zone',
            title: 'Transfer ownership or delete the organization',
            keywords: ['delete', 'owner', 'transfer'],
          },
        ],
      },
      {
        id: 'modules',
        title: 'Modules',
        description: 'Turn product modules on or off for this organization.',
        url: '/settings/modules',
        icon: Boxes,
        permission: Permission.TeamUpdate,
        keywords: ['features', 'enable', 'disable'],
      },
      {
        id: 'limits',
        title: 'Usage & limits',
        description: 'The limits that apply to this organization and what it uses.',
        url: '/settings/limits',
        icon: Gauge,
        permission: Permission.TeamUpdate,
        keywords: ['limits', 'quota', 'seats', 'usage'],
        onlyWhenLimitsApply: true,
      },
    ],
  },
  {
    id: 'security',
    title: 'Security',
    items: [
      {
        // The organization's posture checks and score (api: GET
        // /organization/security-overview, owners and admins): the Security
        // group's landing page.
        id: 'security-overview',
        title: 'Security overview',
        description: 'A score and checklist of what to fix first in your organization.',
        url: '/settings/security',
        icon: ShieldAlert,
        permission: Permission.TeamUpdate,
        keywords: ['security', 'health', 'score', 'checklist', 'posture', '2fa', 'mfa'],
      },
      {
        id: 'authentication',
        title: 'Authentication',
        description: 'Two-factor, who may join, the IP allowlist and email verification.',
        url: '/settings/authentication',
        icon: LockKeyhole,
        permission: Permission.TeamUpdate,
        keywords: ['2fa', 'mfa', 'ip allowlist', 'domains', 'sso', 'saml', 'sign-in'],
        anchors: [
          {
            id: 'two-factor',
            title: 'Require two-factor authentication',
            keywords: ['2fa', 'mfa', 'totp'],
          },
          { id: 'sso-member-approval', title: 'Approve new SSO members', keywords: ['jit', 'sso'] },
          { id: 'email-verification', title: 'Email verification', keywords: ['verify email'] },
          {
            id: 'allowed-domains',
            title: 'Allowed email domains',
            keywords: ['domain', 'restrict'],
          },
          {
            id: 'ip-allowlist',
            title: 'IP allowlist',
            keywords: ['ip', 'network', 'cidr', 'whitelist'],
          },
          {
            id: 'invitations',
            title: 'Who may be invited',
            keywords: ['invite', 'external', 'guest'],
          },
          {
            id: 'personal-accounts',
            title: 'Personal accounts and SSO exceptions',
            keywords: ['gmail', 'personal email', 'break-glass'],
          },
        ],
      },
      {
        // What the verified SSO domains do to accounts on them (api RFC-104):
        // read by owners and admins, changed by owners only.
        id: 'domains',
        title: 'Domains',
        description: 'Who may join with your domain, and whether it must use single sign-on.',
        url: '/settings/domains',
        icon: Globe,
        permission: Permission.TeamUpdate,
        keywords: ['domain', 'join', 'sign up', 'sso required', 'workspace', 'claim'],
      },
      {
        // Two-sided trusts with partner organizations (api RFC-058): read by
        // owners and admins, changed by owners only.
        id: 'trusted-organizations',
        title: 'Trusted organizations',
        description: 'Partner organizations whose people sign in here with their own SSO.',
        url: '/settings/trusted-organizations',
        icon: Handshake,
        permission: Permission.TeamUpdate,
        keywords: ['trust', 'partner', 'sister company', 'external', 'home realm', 'sso'],
      },
      {
        // Owners approve or reject SSO changes the platform administrator
        // proposed (RFC-022 revision 8); the page tells admins it is owner only.
        id: 'sso-approvals',
        title: 'SSO approvals',
        description: 'Approve or reject sign-in changes proposed by the platform administrator.',
        url: '/settings/sso-approvals',
        icon: ShieldCheck,
        permission: Permission.TeamUpdate,
        keywords: ['sso', 'saml', 'identity provider', 'approval', 'owner'],
      },
      {
        // Time-boxed, read-only, audited access for platform support (api
        // RFC-063): owners grant, owners and admins revoke and see history.
        id: 'support-access',
        title: 'Support access',
        description: 'Let platform support read your data for a limited time.',
        url: '/settings/support-access',
        icon: LifeBuoy,
        permission: Permission.TeamUpdate,
        keywords: ['support', 'help', 'troubleshoot', 'grant', 'revoke', 'case'],
      },
      {
        id: 'audit-log',
        title: 'Audit log',
        description: 'Who did what, and when, across the organization.',
        url: '/settings/audit-log',
        icon: History,
        permission: Permission.AuditRead,
        keywords: ['audit trail', 'events', 'compliance'],
      },
    ],
  },
  {
    id: 'access',
    title: 'Access',
    items: [
      {
        id: 'members',
        title: 'Members',
        description: 'People in the organization, their roles and invitations.',
        url: '/settings/members',
        icon: Users,
        permission: Permission.MembersRead,
        keywords: ['users', 'invite', 'people'],
      },
      {
        id: 'teams',
        title: 'Teams',
        description: 'Groups of members, the assets they see, and the rules that assign assets.',
        url: '/settings/teams',
        icon: FolderKey,
        permission: Permission.GroupsRead,
        keywords: [
          'groups',
          'data scope',
          'assignment rules',
          'ownership',
          'routing',
          'members without a team',
          'default access',
        ],
      },
      {
        id: 'roles',
        title: 'Roles',
        description: 'Custom roles and the permissions they grant.',
        url: '/settings/roles',
        icon: Key,
        permission: Permission.RolesRead,
        keywords: ['rbac', 'permissions'],
      },
      {
        id: 'scim',
        title: 'Directory sync (SCIM)',
        description: 'Provision members from your identity provider.',
        url: '/settings/scim',
        icon: UserCog,
        permission: Permission.MembersRead,
        keywords: ['scim', 'provisioning', 'okta', 'entra', 'azure ad', 'directory'],
      },
      {
        id: 'api-keys',
        title: 'API keys',
        description: 'Keys for scripts and tools that call the API.',
        url: '/settings/api-keys',
        icon: KeyRound,
        permission: Permission.ApiKeysRead,
        keywords: ['token', 'programmatic', 'automation'],
      },
      {
        // An organization-owned identity for an integration, with its own
        // roles, teams and API keys. Not module gated: the API gates none of
        // its routes on the integrations module.
        id: 'service-accounts',
        title: 'Service accounts',
        description: 'Identities for integrations, with their own roles and API keys.',
        url: '/settings/service-accounts',
        icon: ServerCog,
        permission: Permission.MembersRead,
        keywords: [
          'service account',
          'machine',
          'bot',
          'integration identity',
          'api key',
          'non-human',
        ],
      },
      {
        id: 'mcp',
        title: 'AI assistants (MCP)',
        description: 'Let AI assistants work with your data over MCP; approve applications.',
        url: '/settings/mcp',
        icon: Bot,
        permission: Permission.ApiKeysRead,
        keywords: ['mcp', 'claude', 'llm', 'assistant', 'publisher', 'approve', 'request'],
      },
    ],
  },
  {
    id: 'findings',
    title: 'Findings & assets',
    items: [
      {
        id: 'finding-lifecycle',
        title: 'Finding lifecycle',
        description: 'Your own sub-statuses, moves and the requirements each move needs.',
        url: '/settings/finding-lifecycle',
        icon: GitBranch,
        permission: Permission.FindingsRead,
        module: 'findings',
        keywords: ['sub-status', 'status', 'transition', 'move', 'lifecycle', 'publish'],
      },
      {
        id: 'finding-approvals',
        title: 'Finding approvals',
        description: 'Who decides false positives and accepted risks, and who is told.',
        url: '/settings/finding-approvals',
        icon: ClipboardCheck,
        permission: Permission.SettingsRead,
        keywords: ['approval', 'four-eyes', 'false positive', 'accepted risk', 'backup contact'],
      },
      {
        id: 'risk-scoring',
        title: 'Risk scoring',
        description: 'How asset risk scores are weighted.',
        url: '/settings/risk-scoring',
        icon: Scale,
        permission: Permission.TeamUpdate,
        module: 'risk_scoring',
        keywords: ['score', 'weights', 'presets'],
      },
      {
        id: 'sla-policies',
        title: 'SLA policies',
        description: 'Remediation deadlines per severity.',
        url: '/settings/sla-policies',
        icon: Timer,
        permission: Permission.SLARead,
        module: 'sla',
        keywords: ['sla', 'deadline', 'due date'],
      },
      {
        id: 'vulnerability-matching',
        title: 'Vulnerability matching',
        description: 'Which CVEs affecting your software versions become findings.',
        url: '/settings/vulnerability-matching',
        icon: Bug,
        permission: Permission.TeamUpdate,
        keywords: ['cve', 'version', 'software', 'nvd', 'banner', 'match'],
      },
      {
        id: 'emerging-threats',
        title: 'Emerging threats',
        description: 'When new or newly exploited CVEs alert you, and how.',
        url: '/settings/emerging-threats',
        icon: Siren,
        permission: Permission.TeamUpdate,
        keywords: ['cve', 'kev', 'epss', 'alert', 'digest', 'quiet hours', 'exploited', 'zero-day'],
      },
      {
        id: 'license-policy',
        title: 'License policy',
        description: 'Which open-source licenses your packages may use, and which open findings.',
        url: '/settings/license-policy',
        icon: FileBadge,
        permission: Permission.SettingsRead,
        keywords: ['license', 'spdx', 'copyleft', 'gpl', 'sbom', 'compliance'],
      },
      {
        id: 'asset-sources',
        title: 'Asset sources',
        description: 'Which source decides asset criticality, owner and exposure.',
        url: '/settings/asset-sources',
        icon: GitMerge,
        permission: Permission.TeamUpdate,
        keywords: ['source', 'precedence', 'integration', 'import', 'scan', 'lock', 'conflict'],
      },
      {
        id: 'asset-lifecycle',
        title: 'Asset lifecycle',
        description: 'When stale assets are retired automatically.',
        url: '/settings/asset-lifecycle',
        icon: Clock,
        permission: Permission.TeamUpdate,
        keywords: ['stale', 'retire', 'archive'],
      },
      {
        id: 'pentest-methodology',
        title: 'Pentest methodology',
        description:
          'Campaign types, methodologies, checklists, the finding library and report templates.',
        url: '/settings/pentest',
        icon: Crosshair,
        permission: Permission.PentestRead,
        module: 'pentest',
        keywords: [
          'pentest',
          'campaign types',
          'methodology',
          'checklist',
          'checklists',
          'finding library',
          'templates',
          'report templates',
          'word',
          'docx',
        ],
      },
    ],
  },
  {
    id: 'scanning',
    title: 'Scanning',
    items: [
      {
        id: 'scope-policy',
        title: 'Scope policy',
        description: 'Who widens scope, how many approve, one-off entries and discovered names.',
        url: '/settings/scope',
        icon: Crosshair,
        permission: Permission.ScopeRead,
        module: 'scope_config',
        keywords: ['scope', 'approvals', 'one-off', 'exception', 'tier', 'auto-join', 'proof'],
      },
      {
        id: 'scan-approval',
        title: 'Scan approval',
        description: 'Which scans need a person’s approval before they run: off by default.',
        url: '/settings/scanning/scan-approval',
        icon: ShieldCheck,
        permission: Permission.ScansRead,
        module: 'scans',
        keywords: [
          'approval',
          'approve',
          'governance',
          'intrusive',
          'change advisory',
          'four eyes',
        ],
      },
      {
        id: 'scan-windows',
        title: 'Scan windows',
        description: 'When scans may touch which targets: testing windows and blackouts.',
        url: '/settings/scanning/scan-windows',
        icon: CalendarClock,
        permission: Permission.ScansRead,
        module: 'scans',
        keywords: [
          'business hours',
          'maintenance window',
          'change freeze',
          'blackout',
          'testing window',
          'freeze window',
          'schedule',
        ],
      },
      {
        // The sensor scan-job controls of the security settings section (the
        // same API section as Authentication, owner only to change): what
        // jobs may do on the organization's sensors.
        id: 'sensor-safety',
        title: 'Sensor job safety',
        description:
          'What scan jobs may do on your sensors: private targets, callbacks, custom templates, TLS.',
        url: '/settings/scanning/sensor-safety',
        icon: ShieldHalf,
        permission: Permission.TeamUpdate,
        module: 'sensors',
        keywords: [
          'interactsh',
          'out-of-band',
          'custom templates',
          'user-agent',
          'tls',
          'private targets',
          'local policy',
          'shared sensors',
          'key binding',
        ],
        anchors: [
          {
            id: 'private-targets',
            title: 'Private targets need a sensor-local policy',
            keywords: ['rfc 1918', 'internal'],
          },
          {
            id: 'opt-ins',
            title: 'Out-of-band callbacks and custom templates',
            keywords: ['interactsh', 'oob', 'templates'],
          },
          {
            id: 'tool-http',
            title: 'User-Agent and TLS of scan tools',
            keywords: ['user agent', 'certificate', 'insecure'],
          },
          {
            id: 'sensor-policies',
            title: 'Sensor identity and key binding',
            keywords: ['identity', 'key binding'],
          },
          {
            id: 'shared-sensors',
            title: 'Shared sensors',
            keywords: ['platform sensors', 'opt out'],
          },
        ],
      },
      {
        id: 'scan-profiles',
        title: 'Scan profiles',
        description: 'Reusable scan configurations: tools, intensity and duration.',
        url: '/settings/scanning/profiles',
        icon: FileSliders,
        permission: Permission.ScanProfilesRead,
        module: 'scans',
        keywords: ['profiles', 'scan config'],
      },
      {
        id: 'tools',
        title: 'Tools',
        description: 'The tools your sensors have, and whether a scan can run with each.',
        url: '/settings/scanning/tools',
        icon: Wrench,
        permission: Permission.ToolsRead,
        module: 'scans',
        keywords: ['scanners', 'tool registry', 'tool availability'],
      },
      {
        id: 'tool-defaults',
        title: 'Tool defaults',
        description: 'Default options for each tool on every sensor; a sensor can override them.',
        url: '/settings/scanning/tool-defaults',
        icon: SlidersHorizontal,
        permission: Permission.SensorsRead,
        module: 'sensors',
        keywords: ['tool settings', 'rate limit', 'concurrency', 'timeout', 'retries', 'options'],
      },
      {
        id: 'sensor-products',
        title: 'Sensor products',
        description: 'Latest and minimum release of the sensors your organization builds.',
        url: '/settings/scanning/sensor-products',
        icon: Package,
        permission: Permission.SensorsRead,
        module: 'sensors',
        keywords: ['custom sensor', 'sdk-go', 'release', 'update available', 'unsupported'],
      },
      {
        id: 'capabilities',
        title: 'Capabilities',
        description: 'The capability taxonomy that tools are matched on.',
        url: '/settings/scanning/capabilities',
        icon: Zap,
        permission: Permission.ToolsRead,
        module: 'scans',
        keywords: ['taxonomy'],
      },
    ],
  },
  {
    id: 'content',
    title: 'Scanner content',
    items: [
      {
        // Signed content packages from the catalog (api RFC-099): read with
        // content:read; installs and approvals need content:install.
        id: 'content',
        title: 'Content catalog',
        description: 'Signed rules, templates and other packages: install, update and approve.',
        url: '/settings/content',
        icon: Package,
        permission: Permission.ContentRead,
        keywords: ['content', 'packages', 'catalog', 'install', 'rules', 'templates', 'signed'],
      },
      {
        id: 'scanner-templates',
        title: 'Scanner templates',
        description: 'Custom Nuclei, Semgrep and Betterleaks templates.',
        url: '/settings/scanning/templates',
        icon: FileCode2,
        permission: Permission.ScannerTemplatesRead,
        module: 'scanner_templates',
        keywords: ['nuclei', 'semgrep', 'betterleaks', 'gitleaks', 'rules'],
      },
      {
        id: 'template-sources',
        title: 'Template sources',
        description: 'Git, S3 and HTTP sources that keep templates in sync.',
        url: '/settings/scanning/template-sources',
        icon: FolderGit2,
        permission: Permission.TemplateSourcesRead,
        module: 'template_sources',
        keywords: ['git', 's3', 'sync'],
      },
      {
        id: 'source-credentials',
        title: 'Source credentials',
        description: 'Encrypted credentials that template sources use to fetch.',
        url: '/settings/scanning/credentials',
        icon: Lock,
        permission: Permission.SecretStoreRead,
        module: 'scans',
        keywords: ['secret store', 'secrets', 'tokens', 'git token'],
      },
      {
        id: 'scanner-content',
        title: 'Content freshness',
        description: 'How fresh vulnerability databases, templates and rules must be.',
        url: '/settings/scanning/content',
        icon: DatabaseZap,
        permission: Permission.SensorsRead,
        module: 'sensors',
        keywords: ['trivy db', 'nuclei templates', 'semgrep rules', 'staleness', 'pin', 'update'],
      },
    ],
  },
  {
    id: 'integrations',
    title: 'Integrations',
    items: [
      {
        id: 'all-integrations',
        title: 'All integrations',
        description: 'Every connection and its status.',
        url: '/settings/integrations',
        icon: Puzzle,
        permission: Permission.IntegrationsRead,
        module: 'integrations',
        keywords: ['connections', 'catalog'],
      },
      {
        id: 'source-control',
        title: 'Source control',
        description: 'GitHub, GitLab, Bitbucket and Azure DevOps.',
        url: '/settings/integrations/scm',
        icon: GitBranch,
        permission: Permission.IntegrationsRead,
        module: 'integrations',
        subModuleKey: 'scm',
        keywords: ['scm', 'github', 'gitlab', 'bitbucket', 'azure devops'],
      },
      {
        id: 'vulnerability-scanners',
        title: 'Vulnerability scanners',
        description: 'Import Nessus and Tenable scan exports.',
        url: '/settings/integrations/scanners',
        icon: ShieldCheck,
        permission: Permission.IntegrationsRead,
        module: 'integrations',
        subModuleKey: 'scanners',
        keywords: ['tenable', 'nessus', 'import'],
      },
      {
        id: 'ticketing',
        title: 'Ticketing',
        description: 'Jira and other ticketing systems.',
        url: '/settings/integrations/ticketing',
        icon: ListChecks,
        permission: Permission.IntegrationsRead,
        module: 'integrations',
        subModuleKey: 'ticketing',
        keywords: ['jira', 'servicenow', 'tickets'],
      },
      {
        id: 'ticket-field-mapping',
        title: 'Ticket field mapping',
        description: 'Which fields and statuses sync with Jira, per project.',
        url: '/settings/integrations/ticketing/mappings',
        icon: ArrowLeftRight,
        permission: Permission.IntegrationsRead,
        module: 'integrations',
        subModuleKey: 'ticketing',
        keywords: ['jira', 'fields', 'mapping', 'workflow', 'status'],
      },
      {
        id: 'notification-channels',
        title: 'Notification channels',
        description: 'Slack, Teams, Telegram and webhook alerts for the organization.',
        url: '/settings/integrations/notifications',
        icon: MessageSquare,
        permission: Permission.IntegrationsRead,
        module: 'integrations',
        subModuleKey: 'notifications',
        keywords: ['slack', 'teams', 'telegram', 'webhook', 'outbox'],
      },
      {
        id: 'siem',
        title: 'SIEM',
        description: 'Forward security events to Splunk.',
        url: '/settings/integrations/siem',
        icon: Shield,
        permission: Permission.IntegrationsRead,
        module: 'integrations',
        subModuleKey: 'siem',
        keywords: ['splunk', 'hec', 'events'],
      },
    ],
  },
]

/** Every item, in rail order. */
export const settingsNavItems: SettingsNavItem[] = settingsNav.flatMap((g) => g.items)

/**
 * Routes under /settings that keep the app sidebar: creating a new
 * organization is onboarding, not configuration.
 */
const APP_SHELL_UNDER_SETTINGS = ['/settings/tenant/create']

function underPath(pathname: string, base: string): boolean {
  return pathname === base || pathname.startsWith(`${base}/`)
}

/** Whether `pathname` renders the settings shell instead of the app sidebar. */
export function isSettingsShellPath(pathname: string): boolean {
  if (APP_SHELL_UNDER_SETTINGS.some((p) => underPath(pathname, p))) return false
  if (underPath(pathname, '/settings') || underPath(pathname, '/account')) return true
  return settingsNavItems.some((item) => underPath(pathname, item.url))
}

/** The rail item for `pathname`: the longest item url it sits under. */
export function activeSettingsItem(
  pathname: string,
  items: readonly SettingsNavItem[] = settingsNavItems
): SettingsNavItem | undefined {
  return items
    .filter((item) => underPath(pathname, item.url))
    .sort((a, b) => b.url.length - a.url.length)[0]
}

/** Case- and accent-insensitive match of a filter query against an item. */
export function matchesSettingsQuery(
  item: SettingsNavItem,
  query: string,
  labels: { title: string; description: string; group: string }
): boolean {
  return matchesAllWords(query, [
    labels.title,
    labels.description,
    labels.group,
    item.title,
    ...(item.keywords ?? []),
  ])
}
