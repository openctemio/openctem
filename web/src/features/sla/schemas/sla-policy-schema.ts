import { z } from 'zod'

/**
 * Validation for the SLA policy form.
 *
 * Bounds mirror the API validator (CreateSLAPolicyRequest in sla_handler.go):
 * name 1..100, description <=500, each day window a positive int 1..365,
 * warning threshold 0..100. Windows must be non-decreasing: P0 <= P1 <= P2 <=
 * P3 and critical <= high <= medium <= low <= info. A more urgent finding never
 * gets a longer deadline.
 *
 * Info may be 0 = informational findings get no SLA (the default); it then
 * takes no part in the order.
 */

const dayField = z
  .number()
  .int('Whole days only')
  .min(1, 'At least 1 day')
  .max(365, 'At most 365 days')

/** Info days: 0 = no SLA for informational findings. */
export const NO_SLA = 0
const infoDayField = z
  .number()
  .int('Whole days only')
  .min(NO_SLA, '0 (no SLA) or more')
  .max(365, 'At most 365 days')

type DayKey =
  | 'p0_days'
  | 'p1_days'
  | 'p2_days'
  | 'p3_days'
  | 'critical_days'
  | 'high_days'
  | 'medium_days'
  | 'low_days'
  | 'info_days'

/** Pairs [tighter, looser, message]: the first must not exceed the second. */
const WINDOW_ORDER: [DayKey, DayKey, string][] = [
  ['p0_days', 'p1_days', 'P0 must be remediated no later than P1'],
  ['p1_days', 'p2_days', 'P1 must be remediated no later than P2'],
  ['p2_days', 'p3_days', 'P2 must be remediated no later than P3'],
  ['critical_days', 'high_days', 'Critical must be remediated no later than High'],
  ['high_days', 'medium_days', 'High must be remediated no later than Medium'],
  ['medium_days', 'low_days', 'Medium must be remediated no later than Low'],
  ['low_days', 'info_days', 'Low must be remediated no later than Info'],
]

export const slaPolicySchema = z
  .object({
    name: z.string().trim().min(1, 'Name is required').max(100, 'At most 100 characters'),
    description: z.string().trim().max(500, 'At most 500 characters').optional(),
    is_default: z.boolean(),
    p0_days: dayField,
    p1_days: dayField,
    p2_days: dayField,
    p3_days: dayField,
    critical_days: dayField,
    high_days: dayField,
    medium_days: dayField,
    low_days: dayField,
    info_days: infoDayField,
    warning_threshold_pct: z
      .number()
      .int('Whole percent only')
      .min(1, 'At least 1')
      .max(100, 'At most 100'),
    escalation_enabled: z.boolean(),
  })
  .superRefine((v, ctx) => {
    for (const [tighter, looser, message] of WINDOW_ORDER) {
      if (looser === 'info_days' && v.info_days === NO_SLA) continue
      if (v[tighter] > v[looser]) {
        ctx.addIssue({ code: 'custom', message, path: [tighter] })
      }
    }
  })

/**
 * Form shape. Declared explicitly rather than via z.infer so the react-hook-form
 * resolver's input/output generics line up (mirrors the scan-profile schema).
 */
export interface SlaPolicyFormData {
  name: string
  description?: string
  is_default: boolean
  p0_days: number
  p1_days: number
  p2_days: number
  p3_days: number
  critical_days: number
  high_days: number
  medium_days: number
  low_days: number
  info_days: number
  warning_threshold_pct: number
  escalation_enabled: boolean
}

/**
 * Platform defaults (pkg/domain/sla: DefaultPriorityDays, DefaultSLADays, the
 * 80 % warning and escalation on). A new policy starts here.
 */
export const DEFAULT_SLA_FORM: SlaPolicyFormData = {
  name: '',
  description: '',
  is_default: true,
  p0_days: 2,
  p1_days: 5,
  p2_days: 15,
  p3_days: 30,
  critical_days: 2,
  high_days: 15,
  medium_days: 30,
  low_days: 60,
  info_days: NO_SLA,
  warning_threshold_pct: 80,
  escalation_enabled: true,
}
