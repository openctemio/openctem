/**
 * Types of the groups that fill themselves: the rule document, its preview,
 * pasted lists and the membership history. They follow the API's JSON.
 */

/** How an asset came into a group. */
export type GroupMemberSource = 'rule' | 'manual' | 'paste'

/** The assets list filter a rule applies (the Assets list parameter names). */
export interface GroupRuleFilter {
  name?: string
  types?: string[]
  lenses?: string[]
  criticalities?: string[]
  statuses?: string[]
  scopes?: string[]
  exposures?: string[]
  tags?: string[]
  tags_mode?: 'any' | 'all'
  exclude_tags?: string[]
  search?: string
  min_risk_score?: number
  max_risk_score?: number
  has_findings?: boolean
  is_crown_jewel?: boolean
  sub_type?: string
  business_unit_ids?: string[]
  owner_ids?: string[]
  in_cidr?: string[]
  has_owner?: boolean
  data_classifications?: string[]
  is_control_plane?: boolean
  internet_facing?: boolean
  environments?: string[]
  providers?: string[]
  attribution?: string[]
  scope_status?: string[]
  technology?: string[]
  technology_category?: string[]
  freshness?: string
  coverage?: string
}

export interface GroupRuleDomain {
  name: string
  subdomains: boolean
}

/** The stored rule document. */
export interface GroupRuleDocument {
  v: 1
  filter: GroupRuleFilter
  domains?: GroupRuleDomain[]
  covered_by?: string[]
  include_related?: boolean
}

export type GroupRuleStatus = 'idle' | 'ok' | 'paused' | 'over_cap'

/** A group's rule and how its last evaluation went. */
export interface GroupRule {
  document: GroupRuleDocument
  status: GroupRuleStatus
  evaluated_at?: string
  excluded: number
  cap: number
}

export interface GroupRuleUse {
  id: string
  name: string
  privileged?: boolean
}

/** What a change means for the teams and scans that use the group. */
export interface GroupRuleImpact {
  widens: boolean
  would_join: number
  teams: GroupRuleUse[]
  scans: GroupRuleUse[]
  privileged_team: boolean
}

export interface GroupRulePreviewAsset {
  id: string
  name: string
  type: string
}

export interface GroupRulePreview {
  count: number
  cap: number
  over_cap: boolean
  sample: GroupRulePreviewAsset[]
  would_join: number
  would_leave: number
  impact?: GroupRuleImpact
}

export interface SetGroupRuleResult {
  rule?: GroupRule
  joined: number
  left: number
  impact: GroupRuleImpact
}

export interface PasteLineInfo {
  line: number
  value: string
  kind: 'domain' | 'ip' | 'cidr' | 'url'
}

export interface PasteRejectedLine {
  line: number
  value: string
  reason: string
}

export interface PasteGroupResult {
  lines: number
  matched: number
  added: number
  created: number
  candidates: number
  skipped: number
  not_found: number
  missing_sample: PasteLineInfo[]
  rejected: PasteRejectedLine[]
  impact?: GroupRuleImpact
}

export interface AddMatchingResult {
  matched: number
  added: number
  impact?: GroupRuleImpact
}

export type GroupHistoryReason =
  'matches_rule' | 'no_longer_matches' | 'added_by_hand' | 'added_by_paste' | 'removed_by_hand'

export interface GroupHistoryEntry {
  id: string
  group_id: string
  group_name?: string
  asset_id: string
  asset_name: string
  action: 'joined' | 'left'
  source: GroupMemberSource
  reason: GroupHistoryReason
  created_at: string
}

export interface GroupHistoryResponse {
  data: GroupHistoryEntry[]
  total: number
  page: number
  per_page: number
  total_pages: number
}
