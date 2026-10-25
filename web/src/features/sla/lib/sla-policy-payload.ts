import type { CreateSlaPolicyInput, UpdateSlaPolicyInput } from '../api/use-sla-policies-api'
import type { SlaPolicyFormData } from '../schemas/sla-policy-schema'

/**
 * The request body the policy dialog sends.
 *
 * `is_default` is never sent as true from the dialog: making a policy the
 * default tightens every open finding's deadline irreversibly, so it is its own
 * confirmed action ("Make default" on the policy list). Create sends an
 * explicit false; edit leaves the flag out so a save never changes it.
 */
export function buildSlaPolicyPayload(
  data: SlaPolicyFormData,
  isEdit: boolean
): CreateSlaPolicyInput & UpdateSlaPolicyInput {
  return {
    name: data.name,
    // An empty string clears the description (absent would keep the old one).
    description: data.description ?? '',
    ...(isEdit ? {} : { is_default: false }),
    p0_days: data.p0_days,
    p1_days: data.p1_days,
    p2_days: data.p2_days,
    p3_days: data.p3_days,
    critical_days: data.critical_days,
    high_days: data.high_days,
    medium_days: data.medium_days,
    low_days: data.low_days,
    info_days: data.info_days,
    kev_cap_days: data.kev_cap_days,
    warning_threshold_pct: data.warning_threshold_pct,
    escalation_enabled: data.escalation_enabled,
  }
}
