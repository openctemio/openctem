import type { OwnershipType } from '../types'
import { OWNERSHIP_TYPE_DESCRIPTIONS, OWNERSHIP_TYPE_LABELS } from '../types'
import type { TFn } from './default-t'

/** An owner's role in the console's language ("Primary", "Chính"). */
export function ownershipTypeLabel(t: TFn, type: OwnershipType): string {
  return t(`assets.ownershipType.${type}`, OWNERSHIP_TYPE_LABELS[type] ?? type)
}

/** What a role means, for the owner pickers, in the console's language. */
export function ownershipTypeHint(t: TFn, type: OwnershipType): string {
  return t(`assets.ownershipType.${type}Hint`, OWNERSHIP_TYPE_DESCRIPTIONS[type] ?? '')
}

/** Every role, in the order of the pickers. */
export const OWNERSHIP_TYPES = Object.keys(OWNERSHIP_TYPE_LABELS) as OwnershipType[]
