/**
 * Notification-channel filters, shared by the add and edit dialogs and the
 * channel list.
 *
 * The API reads an empty severity or event-type list as "use the defaults"
 * (critical + high, three default events), so a channel saved with every box
 * unticked came back with the defaults ticked (23a B17). An empty selection is
 * therefore refused here; the way to silence a channel is to disable it.
 */
import { z } from 'zod'
import type { NotificationSeverity } from '@/features/integrations/types/integration.types'
import { SEVERITY_LEVELS } from '@/lib/severity'

export const EMPTY_SEVERITIES_MESSAGE =
  'Select at least one severity. To stop this channel, disable it instead.'
export const EMPTY_EVENT_TYPES_MESSAGE =
  'Select at least one event type. To stop this channel, disable it instead.'

export const enabledSeveritiesSchema = z
  .array(z.enum(['critical', 'high', 'medium', 'low', 'info', 'none']))
  .min(1, EMPTY_SEVERITIES_MESSAGE)

export const enabledEventTypesSchema = z.array(z.string()).min(1, EMPTY_EVENT_TYPES_MESSAGE)

/** The real finding severities; "none" (no severity) is an extra opt-in. */
const REAL_SEVERITIES: NotificationSeverity[] = [...SEVERITY_LEVELS]

/**
 * True only when every real severity is enabled. The list used to say "All
 * severities" for any five of the six values, so a channel without Critical
 * was labelled as receiving everything.
 */
export function coversAllSeverities(severities: readonly string[] | null | undefined): boolean {
  if (!severities) return false
  return REAL_SEVERITIES.every((s) => severities.includes(s))
}
