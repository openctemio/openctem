/**
 * Route tabs of the pages that have sub-pages. Each list is used twice: the page
 * renders it with `SectionTabs`, and its sidebar item carries it as `sections`
 * so the command palette can still search each sub-page. The sidebar itself
 * shows ONE row per section (at most two nav levels: group, then item).
 */
import {
  AppWindow,
  Briefcase,
  Bug,
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
  GlobeLock,
  History,
  LayoutDashboard,
  Link2,
  ListChecks,
  Network,
  Radar,
  FileBadge,
  ShieldCheck,
  Swords,
  Trophy,
  UserX,
  Gauge,
  Wrench,
  Layers,
} from 'lucide-react'
import type { ElementType } from 'react'
import type { SectionTab } from '@/features/shared/components/section-tabs'
import { Permission } from '@/lib/permissions'

/**
 * Exposures: the attack-surface exposure events (Overview) and four views of
 * findings by type. URLs predate the tabs and are unchanged.
 */
export const EXPOSURES_SECTION_TABS: readonly SectionTab[] = [
  { label: 'Overview', labelKey: 'nav.tab.overview', href: '/exposures', icon: LayoutDashboard },
  {
    label: 'Vulnerabilities',
    labelKey: 'nav.tab.vulnerabilities',
    href: '/exposures/vulnerabilities',
    icon: Bug,
  },
  // FileKey, not KeyRound: KeyRound reads as the separate Credential leaks
  // module (leaked accounts), while this tab is secrets committed to code.
  { label: 'Secrets', labelKey: 'nav.tab.secrets', href: '/exposures/secrets', icon: FileKey },
  {
    label: 'Code weaknesses',
    labelKey: 'nav.tab.codeWeaknesses',
    href: '/exposures/code',
    icon: FileWarning,
  },
  {
    label: 'Misconfigurations',
    labelKey: 'nav.tab.misconfigurations',
    href: '/exposures/misconfigurations',
    icon: Wrench,
  },
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
    labelKey: 'nav.tab.scope',
    href: '/scope',
    icon: Fence,
    module: 'scope_config',
    permission: Permission.ScopeRead,
  },
  {
    // Domains proved by DNS; its own page so Scope keeps one tab row.
    label: 'Domain proof',
    labelKey: 'scope.tabs.proof',
    href: '/scope/domain-proof',
    icon: GlobeLock,
    module: 'attack_surface',
    permission: Permission.ScopeRead,
  },
  {
    label: 'Networks',
    labelKey: 'networkSeeds.tab',
    href: '/scope/networks',
    icon: Network,
    module: 'attack_surface',
    permission: Permission.ScopeRead,
  },
  {
    label: 'Programs',
    labelKey: 'nav.tab.programs',
    href: '/programs',
    icon: Trophy,
    module: 'scope_config',
    permission: Permission.ProgramsRead,
  },
  {
    label: 'Letters',
    labelKey: 'nav.tab.letters',
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
    labelKey: 'nav.tab.crownJewels',
    href: '/crown-jewels',
    icon: Crown,
    module: 'crown_jewels',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Services',
    labelKey: 'nav.tab.services',
    href: '/business-services',
    icon: Briefcase,
    module: 'business_services',
    permission: Permission.BusinessServicesRead,
  },
  {
    label: 'Units',
    labelKey: 'nav.tab.units',
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
    labelKey: 'nav.tab.threats',
    href: '/threat-model',
    icon: Crosshair,
    module: 'threat_model',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Attacker profiles',
    labelKey: 'nav.tab.attackerProfiles',
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
    labelKey: 'nav.tab.scans',
    href: '/scans',
    icon: Radar,
    module: 'scans',
    permission: Permission.ScansRead,
  },
  {
    label: 'Runs',
    labelKey: 'nav.tab.runs',
    href: '/scans/runs',
    icon: ListChecks,
    module: 'scans',
    permission: Permission.ScansRead,
  },
  {
    label: 'Workflows',
    labelKey: 'nav.tab.workflows',
    href: '/scans/workflows',
    icon: GitBranch,
    module: 'scan_workflows',
    permission: Permission.ScanWorkflowsRead,
    keywords: ['pipeline', 'pipelines', 'builder'],
  },
  {
    label: 'Approvals',
    labelKey: 'nav.tab.approvals',
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
    labelKey: 'nav.tab.inventory',
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
    labelKey: 'nav.tab.needsAttention',
    href: '/assets/attention',
    matchPrefix: ['/assets/suggestions', '/assets/duplicates'],
    icon: ListChecks,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Groups',
    labelKey: 'nav.tab.groups',
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
    labelKey: 'nav.tab.activity',
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
  id:
    | 'validate_primary'
    | 'decide_monitoring'
    | 'no_owner'
    | 'context'
    | 'unscanned'
    | 'relationships'
    | 'duplicates'
  /**
   * "Scoping decisions" and "Fix on the asset" reasons are filters of the
   * inventory; "Review" ones have their own rows.
   */
  group: 'decide' | 'fix' | 'review'
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
    // Scoping decisions (research/333 D11): the organization's root domains
    // whose ownership is not settled yet, then every name that waits for a
    // person to decide whether it is monitored.
    id: 'validate_primary',
    group: 'decide',
    label: 'Validate primary assets',
    labelKey: 'assets.attention.tab.validatePrimary',
    whyKey: 'assets.attention.why.validatePrimary',
    why: 'Root domains your discovery starts from, not yet confirmed as yours.',
    unitKey: 'assets.attention.unit.assets',
    unit: ASSETS_UNIT,
    href: '/assets/attention/validate-primary',
    icon: Crown,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    id: 'decide_monitoring',
    group: 'decide',
    label: 'Decide monitoring',
    labelKey: 'assets.attention.tab.decideMonitoring',
    whyKey: 'assets.attention.why.decideMonitoring',
    why: 'Discovered names waiting for a decision: monitor, watch only, or not yours.',
    unitKey: 'assets.attention.unit.assets',
    unit: ASSETS_UNIT,
    href: '/assets/attention/decide-monitoring',
    icon: ListChecks,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
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
    labelKey: 'nav.tab.overview',
    href: '/attack-surface',
    icon: Globe,
    module: 'attack_surface',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Review',
    labelKey: 'nav.tab.review',
    href: '/attack-surface/review',
    icon: ClipboardCheck,
    module: 'attack_surface',
    permission: Permission.AssetsRead,
  },
  {
    label: 'Lookalikes',
    labelKey: 'nav.tab.lookalikes',
    href: '/attack-surface/lookalikes',
    icon: Copy,
    module: 'attack_surface',
    permission: Permission.ScopeRead,
  },
  {
    label: 'Changes',
    labelKey: 'nav.tab.changes',
    href: '/attack-surface/changes',
    icon: History,
    module: 'attack_surface',
    permission: Permission.AssetsRead,
  },
  {
    // The coverage pipeline by stage with Run, Run all and Abort all
    // (research/333 §1.2). The API also needs an unrestricted data scope.
    label: 'Discovery',
    labelKey: 'nav.tab.discovery',
    href: '/attack-surface/discovery',
    icon: Radar,
    module: 'attack_surface',
    permission: Permission.ScansRead,
  },
  {
    // What the web origins serve: endpoints, parameters, the same path across
    // origins and their changes (RFC-056). Its rows are endpoints, not assets,
    // so it sits with the external surface work rather than as an asset lens
    // (research/242 D4). The data is the assets module's.
    label: 'Web surface',
    labelKey: 'nav.tab.webSurface',
    href: '/attack-surface/web',
    icon: AppWindow,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    // The technologies of the external surface by version, with the CVEs of
    // each version (research/333 D4). Read from the assets module's data.
    label: 'Technologies',
    labelKey: 'nav.tab.technologies',
    href: '/attack-surface/technologies',
    icon: Layers,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
  {
    // Every exposure of the external surface with the asset it is on
    // (research/333 D1): open work on monitored assets first.
    label: 'Exposure items',
    labelKey: 'nav.tab.exposureItems',
    href: '/attack-surface/exposures',
    icon: FileWarning,
    module: 'attack_surface',
    permission: Permission.ExposuresRead,
  },
  {
    // The certificate assets of the external surface with their expiry
    // status (research/333 D5). Read from the assets module's data.
    label: 'Certificates',
    labelKey: 'nav.tab.certificates',
    href: '/attack-surface/certificates',
    icon: FileBadge,
    module: 'assets',
    permission: Permission.AssetsRead,
  },
]
