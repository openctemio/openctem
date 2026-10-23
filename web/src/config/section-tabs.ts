/**
 * Route tabs of the pages that have sub-pages. Each list is used twice: the page
 * renders it with `SectionTabs`, and its sidebar item carries it as `sections`
 * so the command palette can still search each sub-page. The sidebar itself
 * shows ONE row per section (at most two nav levels: group, then item).
 */
import {
  AlertTriangle,
  Bug,
  Building,
  Building2,
  ClipboardCheck,
  Copy,
  Container,
  Crosshair,
  Crown,
  Fence,
  FileKey,
  FileSignature,
  FileWarning,
  FolderKanban,
  GitBranch,
  Globe,
  History,
  Link2,
  ListChecks,
  Radar,
  ShieldCheck,
  Swords,
  Trophy,
  Wrench,
} from 'lucide-react'
import type { SectionTab } from '@/features/shared/components/section-tabs'
import { Permission } from '@/lib/permissions'

/**
 * Exposures: the attack-surface exposure events (Overview) and four views of
 * findings by type. URLs predate the tabs and are unchanged.
 */
export const EXPOSURES_SECTION_TABS: readonly SectionTab[] = [
  { label: 'Overview', href: '/exposures', icon: AlertTriangle },
  { label: 'Vulnerabilities', href: '/exposures/vulnerabilities', icon: Bug },
  // FileKey, not KeyRound: KeyRound reads as the separate Credential leaks
  // module (leaked accounts), while this tab is secrets committed to code.
  { label: 'Secrets', href: '/exposures/secrets', icon: FileKey },
  { label: 'Code weaknesses', href: '/exposures/code', icon: FileWarning },
  { label: 'Misconfigurations', href: '/exposures/misconfigurations', icon: Wrench },
]

/**
 * Remediation (api/docs/rfcs/RFC-098-remediation-tasks.md): the fix plan,
 * the suggestions to review, the tasks people work on, and the campaigns
 * that track them.
 */
export const REMEDIATION_SECTION_TABS: readonly SectionTab[] = [
  { label: 'Fix plan', labelKey: 'nav.item.fix-plan', href: '/remediation' },
  { label: 'Suggestions', labelKey: 'nav.item.suggestions', href: '/remediation/suggestions' },
  { label: 'Tasks', labelKey: 'nav.item.tasks', href: '/remediation/tasks' },
  { label: 'Campaigns', labelKey: 'nav.item.campaigns', href: '/remediation/campaigns' },
]

/**
 * Scoping > Scope: the organization's own scope entries and exclusions, and
 * the bug-bounty programs it tests (RFC-065). Each tab carries the route
 * guard's permission, so a researcher with only programs:read sees Programs.
 * Render with `GatedSectionTabs`.
 */
export const SCOPE_SECTION_TABS: readonly SectionTab[] = [
  {
    label: 'Scope',
    href: '/scope',
    icon: Fence,
    module: 'scope_config',
    permission: Permission.ScopeRead,
  },
  {
    label: 'Programs',
    href: '/programs',
    icon: Trophy,
    module: 'scope_config',
    permission: Permission.ProgramsRead,
  },
  {
    label: 'Letters',
    href: '/scope/letters',
    icon: FileSignature,
    module: 'scope_config',
    permission: Permission.ScopeRead,
  },
]

/**
 * Scoping > Business context: the ctem.org Critical Asset Register. Each tab is
 * its own module and keeps its URL; the tab's module and permission are the
 * route guard's (route-permissions.ts), so a tab is shown exactly when its page
 * opens. Render with `GatedSectionTabs`.
 */
export const BUSINESS_CONTEXT_SECTION_TABS: readonly SectionTab[] = [
  {
    label: 'Crown jewels',
    href: '/crown-jewels',
    icon: Crown,
    module: 'crown_jewels',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Services',
    href: '/business-services',
    icon: Building,
    module: 'business_services',
    permission: Permission.BusinessServicesRead,
  },
  {
    label: 'Units',
    href: '/business-units',
    icon: Building2,
    module: 'business_units',
    permission: Permission.AssetsRead,
  },
]

/**
 * Scoping > Threat model: the per-crown-jewel threats and the attacker
 * assumptions they are modelled against. Two modules, one row.
 */
export const THREAT_MODEL_SECTION_TABS: readonly SectionTab[] = [
  {
    label: 'Threats',
    href: '/threat-model',
    icon: Crosshair,
    module: 'threat_model',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Attacker profiles',
    href: '/attacker-profiles',
    icon: Swords,
    module: 'attacker_profiles',
    permission: Permission.AttackerProfilesRead,
  },
]

/**
 * Discovery > Scans: the scan configurations, every run they produced, and the
 * scan workflows (the graph of steps a scan runs). One table per route, so each
 * list keeps plain page, per_page and sort parameters. Workflows is its own
 * module (`scan_workflows`); the keywords keep the older names searchable.
 */
export const SCANS_SECTION_TABS: readonly SectionTab[] = [
  {
    label: 'Scans',
    href: '/scans',
    icon: Radar,
    module: 'scans',
    permission: Permission.ScansRead,
  },
  {
    label: 'Runs',
    href: '/scans/runs',
    icon: ListChecks,
    module: 'scans',
    permission: Permission.ScansRead,
  },
  {
    label: 'Workflows',
    href: '/scans/workflows',
    icon: GitBranch,
    module: 'scan_workflows',
    permission: Permission.ScanWorkflowsRead,
    keywords: ['pipeline', 'pipelines', 'builder'],
  },
  {
    label: 'Approvals',
    href: '/scans/approvals',
    icon: ShieldCheck,
    module: 'scans',
    permission: Permission.ScansRead,
    keywords: ['approval', 'approve', 'governance', 'review'],
  },
]

/**
 * Discovery > Assets: the inventory, the groups that organise it, what changed
 * in it and the relationships detected between assets. Every tab lives under
 * /assets because a URL mirrors its place in the nav (RFC-042 §6.19).
 * Suggestions is its own module (`relationships`).
 */
export const ASSETS_SECTION_TABS: readonly SectionTab[] = [
  {
    label: 'Inventory',
    href: '/assets',
    icon: Container,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    // The data-quality queue (research/233 D8, 242 D3): assets missing an
    // owner, a criticality or a recent scan, relationship suggestions and
    // possible duplicates. Relationships and duplicates keep their own URLs.
    label: 'Needs attention',
    href: '/assets/attention',
    matchPrefix: ['/assets/suggestions', '/assets/duplicates'],
    icon: ListChecks,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Groups',
    href: '/assets/groups',
    icon: FolderKanban,
    module: 'assets',
    permission: Permission.AssetGroupsRead,
  },
  {
    // One feed of what changed on assets: new, gone and newly exposed assets,
    // exposure changes, shadow IT, and value changes (RFC-069, `?view=values`).
    // It keeps the URL the change digest links to.
    label: 'Activity',
    href: '/assets/changes',
    icon: History,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    // Origins, endpoints, path patterns and their changes (RFC-056).
    label: 'Web surface',
    href: '/assets/web',
    icon: Globe,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
]

/**
 * The reasons of Assets › Needs attention, as route tabs under it. The asset
 * reasons are filters of the inventory; Relationships is its own module.
 */
export const ASSET_ATTENTION_TABS: readonly SectionTab[] = [
  {
    label: 'No owner',
    labelKey: 'assets.attention.tab.noOwner',
    href: '/assets/attention',
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Criticality not set',
    labelKey: 'assets.attention.tab.context',
    href: '/assets/attention/context',
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Not scanned',
    labelKey: 'assets.attention.tab.unscanned',
    href: '/assets/attention/unscanned',
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Relationships',
    labelKey: 'assets.attention.tab.relationships',
    href: '/assets/suggestions',
    icon: Link2,
    module: 'relationships',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Possible duplicates',
    labelKey: 'assets.attention.tab.duplicates',
    href: '/assets/duplicates',
    module: 'assets',
    permission: Permission.AssetsRead,
  },
]

/**
 * Attack surface: the EASM overview and the ownership review queue
 * (research/22 P0-12: the queue is one click from the sidebar, with the
 * number of names waiting).
 */
export const ATTACK_SURFACE_SECTION_TABS: readonly SectionTab[] = [
  {
    label: 'Overview',
    href: '/attack-surface',
    icon: Globe,
    module: 'attack_surface',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Suggestions',
    href: '/attack-surface/review',
    icon: ClipboardCheck,
    module: 'attack_surface',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Lookalikes',
    href: '/attack-surface/lookalikes',
    icon: Copy,
    module: 'attack_surface',
    permission: Permission.ScopeRead,
  },
  {
    label: 'Changes',
    href: '/attack-surface/changes',
    icon: History,
    module: 'attack_surface',
    permission: Permission.AssetsRead,
  },
]
