import { Clock } from 'lucide-react'
import {
  CheckCircleGlyph,
  SlashedCircleGlyph,
  type StatusGlyph,
} from '@/components/ui/status-glyphs'
import type { StatusTone } from '@/lib/status-colors'

/**
 * One approval request on the shared workflow tones (research/247 section 4),
 * for finding, scan, scope and exception approvals alike: pending waits on a
 * person, approved is done, and rejected, canceled, expired and superseded
 * ended without the change applying. There is no red tone: a decision is not
 * a failure. This file holds no colour.
 */
export const APPROVAL_TONE: Record<string, { tone: StatusTone; icon: StatusGlyph }> = {
  pending: { tone: 'waiting', icon: Clock },
  approved: { tone: 'resolved', icon: CheckCircleGlyph },
  rejected: { tone: 'closed', icon: SlashedCircleGlyph },
  canceled: { tone: 'closed', icon: SlashedCircleGlyph },
  expired: { tone: 'closed', icon: SlashedCircleGlyph },
  superseded: { tone: 'closed', icon: SlashedCircleGlyph },
}

/** Tone for a status this build does not know: the quiet closed tone. */
export const UNKNOWN_APPROVAL = { tone: 'closed', icon: SlashedCircleGlyph } as const
