import { Ban, CircleSlash, Clock, ShieldAlert, type LucideIcon } from 'lucide-react'
import {
  CheckCircleGlyph,
  SlashedCircleGlyph,
  type StatusGlyph,
} from '@/components/ui/status-glyphs'
import type { StatusTone } from '@/lib/status-colors'
import type { SuppressionStatus, SuppressionType } from '../types'

/**
 * Approval of an exception rule on the shared workflow tones (research/247
 * section 4): pending waits on a person, approved is done, rejected and
 * expired ended without the rule applying. No red: a decision is not a failure.
 */
export const SUPPRESSION_STATUS_TONE: Record<
  SuppressionStatus,
  { tone: StatusTone; icon: StatusGlyph | LucideIcon }
> = {
  pending: { tone: 'waiting', icon: Clock },
  approved: { tone: 'resolved', icon: CheckCircleGlyph },
  rejected: { tone: 'closed', icon: SlashedCircleGlyph },
  expired: { tone: 'closed', icon: SlashedCircleGlyph },
}

/**
 * The exception type is a classification (a plain tag with an icon), never a
 * colour: accepted risk is not violet, which is reserved for priority.
 */
export const SUPPRESSION_TYPE_ICON: Record<SuppressionType, LucideIcon> = {
  false_positive: CircleSlash,
  accepted_risk: ShieldAlert,
  wont_fix: Ban,
}
