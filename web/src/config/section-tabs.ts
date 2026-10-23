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
  UserX,
  Gauge,
  Wrench,
} from 'lucide-react'
import type { ElementType } from 'react'
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
]

/**
 * A reason on Assets › Needs attention (research/249). The landing lists them
 * as a queue list and each queue page keeps its own route; this registry is
 * the one source of order, gate, label, why line and unit for both, and for
 * the switch menu. The order is fixed (by kind), never sorted by count.
 */
export interface AttentionReasonDef {
  id: 'no_owner' | 'context' | 'unscanned' | 'relationships' | 'duplicates'
  /** "Fix on the asset" reasons are filters of the inventory; "Review" ones have their own rows. */
  group: 'fix' | 'review'
  label: string
  labelKey: string
  whyKey: string
  why: string
  /** Unit after the count: an ICU plural of `count`. */
  unitKey: string
  unit: string
  href: string
  icon: ElementType
  module: string
  permission: string
}

const ASSETS_UNIT = '{count, plural, one {asset} other {assets}}'

export const ASSET_ATTENTION_REASONS: readonly AttentionReasonDef[] = [
  {
    id: 'no_owner',
    group: 'fix',
    label: 'No owner',
    labelKey: 'assets.attention.tab.noOwner',
    whyKey: 'assets.attention.why.noOwner',
    why: 'Findings on these assets have nobody to assign to.',
    unitKey: 'assets.attention.unit.assets',
    unit: ASSETS_UNIT,
    href: '/assets/attention/no-owner',
    icon: UserX,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    id: 'context',
    group: 'fix',
    label: 'Criticality not set',
    labelKey: 'assets.attention.tab.context',
    whyKey: 'assets.attention.why.context',
    why: 'Priority uses the default weight for them.',
    unitKey: 'assets.attention.unit.assets',
    unit: ASSETS_UNIT,
    href: '/assets/attention/context',
    icon: Gauge,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    id: 'unscanned',
    group: 'fix',
    label: 'Not scanned in 30 days',
    labelKey: 'assets.attention.tab.unscanned',
    whyKey: 'assets.attention.why.unscanned',
    why: 'No successful scan, so new exposures on them go unseen.',
    unitKey: 'assets.attention.unit.assets',
    unit: ASSETS_UNIT,
    href: '/assets/attention/unscanned',
    icon: Radar,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    id: 'relationships',
    group: 'review',
    label: 'Relationships',
    labelKey: 'assets.attention.tab.relationships',
    whyKey: 'assets.attention.why.relationships',
    why: 'Links found between assets that wait for a yes or no.',
    unitKey: 'assets.attention.unit.toReview',
    unit: 'to review',
    href: '/assets/suggestions',
    icon: Link2,
    module: 'relationships',
    permission: Permission.AssetsRead,
  },
  {
    id: 'duplicates',
    group: 'review',
    label: 'Possible duplicates',
    labelKey: 'assets.attention.tab.duplicates',
    whyKey: 'assets.attention.why.duplicates',
    why: 'Assets that look like one thing under two names.',
    unitKey: 'assets.attention.unit.pairs',
    unit: '{count, plural, one {pair} other {pairs}}',
    href: '/assets/duplicates',
    icon: Copy,
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
    label: 'Review',
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
  {
    // What the web origins serve: endpoints, parameters, the same path across
    // origins and their changes (RFC-056). Its rows are endpoints, not assets,
    // so it sits with the external surface work rather than as an asset lens
    // (research/242 D4). The data is the assets module's.
    label: 'Web surface',
    href: '/attack-surface/web',
    icon: Globe,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
]
