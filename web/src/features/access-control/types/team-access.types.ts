/**
 * Team access presets (api RFC-127): a team carries access through presets
 * (role templates, each a managed role of the team) and a scope mode.
 */

export type TeamScopeMode = 'specific' | 'all_assets'

/** One preset of a team. */
export interface TeamPreset {
  template_id: string
  role_id: string
  name: string
  version_taken: number
  current_version: number
  update_available: boolean
  privileged: boolean
  has_full_data_access: boolean
}

/** GET /api/v1/groups/{groupId}/access */
export interface TeamAccess {
  presets: TeamPreset[]
  scope_mode: TeamScopeMode
  /** The team carries elevated access: only an owner changes it. */
  privileged: boolean
  /** Roles bound to the team by hand. */
  other_roles: number
}

export interface SetTeamAccessInput {
  presets: string[]
  scope_mode: TeamScopeMode
}

/** A role template a team can use as a preset (GET /api/v1/roles/templates). */
export interface TeamPresetTemplate {
  id: string
  version: number
  name: string
  description: string
  personas: string[]
  has_full_data_access: boolean
}

/** One role a person holds through a team (GET /api/v1/users/{userId}/team-access). */
export interface UserTeamAccess {
  group_id: string
  group_name: string
  role_id: string
  role_name: string
  managed: boolean
  template_id?: string
  privileged: boolean
  member_until?: string
}
