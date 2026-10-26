/**
 * Create Group Dialog Types
 *
 * Form data and related types for the create group wizard
 */

import type { Environment, Criticality } from '@/features/shared/types'
import type { AssetType } from '@/features/assets/types'
import { EMPTY_RULE_DRAFT, type RuleDraft } from '../../lib/group-rule'

/**
 * New asset to be created with the group
 */
export interface NewAssetFormData {
  id: string // Temporary ID for UI tracking
  type: AssetType
  name: string
  description?: string
  tags: string[]
}

/**
 * Form data for creating a new group
 */
export interface CreateGroupFormData {
  // Basic info
  name: string
  description: string
  environment: Environment
  criticality: Criticality

  // Business Context (CTEM Scoping)
  businessUnit: string
  owner: string
  ownerEmail: string
  tags: string[]

  // Assets
  selectedAssetIds: string[] // Existing ungrouped assets to add
  newAssets: NewAssetFormData[] // New assets to create

  // Members that fill themselves, and a pasted list
  rule: RuleDraft // the rule of the group (empty draft: no rule)
  pasteText: string
  pasteCreateMissing: boolean
}

/**
 * Default form data
 */
export const DEFAULT_CREATE_GROUP_FORM: CreateGroupFormData = {
  name: '',
  description: '',
  environment: 'production',
  criticality: 'medium',
  businessUnit: '',
  owner: '',
  ownerEmail: '',
  tags: [],
  selectedAssetIds: [],
  newAssets: [],
  rule: EMPTY_RULE_DRAFT,
  pasteText: '',
  pasteCreateMissing: false,
}
