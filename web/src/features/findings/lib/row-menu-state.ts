/**
 * Which row menu items do not apply to a finding in its current state, from
 * what the list row itself carries (no request per row). The menu shows such
 * an item disabled with the reason; the full rules (the API's transition
 * engine, a pending approval) are applied where the change is made, in the
 * drawer.
 */

import { FINDING_STATUS_CONFIG, type Finding } from '../types'
import { isTriageLocked } from './finding-detail'

/** The part of a list row the menu's state rules read. */
export type RowMenuFinding = Pick<Finding, 'status' | 'source' | 'workItemUris'>

/** Why an item does not apply; the menu translates it (`findings.row.reason.<code>`). */
export type RowMenuBlock = 'managedElsewhere' | 'alreadyFalsePositive' | 'closed' | 'ticketLinked'

export type RowMenuGatedAction = 'assign' | 'status' | 'false_positive' | 'create_ticket'

export const ROW_MENU_REASON_FALLBACK: Record<RowMenuBlock, string> = {
  managedElsewhere: 'People reported this finding, so it is decided in its own workflow.',
  alreadyFalsePositive: 'This finding is already marked as false positive.',
  closed: 'This finding is closed. Reopen it first.',
  ticketLinked: 'This finding already has a linked ticket.',
}

/** The items that do not apply to this finding, each with its reason code. */
export function rowMenuBlocks(
  finding: RowMenuFinding
): Partial<Record<RowMenuGatedAction, RowMenuBlock>> {
  const blocks: Partial<Record<RowMenuGatedAction, RowMenuBlock>> = {}
  // The drawer locks status and assignee for these findings (one rule for both).
  if (isTriageLocked(finding.source)) {
    blocks.assign = 'managedElsewhere'
    blocks.status = 'managedElsewhere'
    blocks.false_positive = 'managedElsewhere'
  } else if (finding.status === 'false_positive') {
    blocks.false_positive = 'alreadyFalsePositive'
  } else if (FINDING_STATUS_CONFIG[finding.status]?.category === 'closed') {
    // A closed finding only reopens; a disposition starts from an open one.
    blocks.false_positive = 'closed'
  }
  if ((finding.workItemUris?.length ?? 0) > 0) blocks.create_ticket = 'ticketLinked'
  return blocks
}
