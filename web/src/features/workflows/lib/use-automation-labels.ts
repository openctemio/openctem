'use client'

import { useMemo } from 'react'

import { useTranslation } from '@/context/i18n-provider'

// Static keys per type (never built from a template string) so the key
// checker and a grep can find every one. Each entry is [key, English]. These
// are names only: what the builder offers comes from GET /workflows/catalog,
// and a type without a name here shows as its id.
const TRIGGER: Record<string, [string, string]> = {
  manual: ['automations.triggerType.manual', 'Manual'],
  finding_created: ['automations.triggerType.finding_created', 'Finding Created'],
  finding_status_changed: [
    'automations.triggerType.finding_status_changed',
    'Finding Status Changed',
  ],
  asset_discovered: ['automations.triggerType.asset_discovered', 'Asset Discovered'],
  scan_completed: ['automations.triggerType.scan_completed', 'Scan Completed'],
  ai_triage_completed: ['automations.triggerType.ai_triage_completed', 'AI Triage Completed'],
  ai_triage_failed: ['automations.triggerType.ai_triage_failed', 'AI Triage Failed'],
}

const ACTION: Record<string, [string, string]> = {
  assign_user: ['automations.actionType.assign_user', 'Assign User'],
  update_status: ['automations.actionType.update_status', 'Update Status'],
  add_tags: ['automations.actionType.add_tags', 'Add Tags'],
  remove_tags: ['automations.actionType.remove_tags', 'Remove Tags'],
  create_ticket: ['automations.actionType.create_ticket', 'Create Ticket'],
  update_ticket: ['automations.actionType.update_ticket', 'Update Ticket'],
  trigger_scan: ['automations.actionType.trigger_scan', 'Trigger Scan'],
  trigger_ai_triage: ['automations.actionType.trigger_ai_triage', 'Run AI Triage'],
  request_false_positive: [
    'automations.actionType.request_false_positive',
    'Request False Positive',
  ],
  request_risk_acceptance: [
    'automations.actionType.request_risk_acceptance',
    'Request Risk Acceptance',
  ],
}

const NOTIFICATION: Record<string, [string, string]> = {
  slack: ['automations.notificationType.slack', 'Slack'],
  email: ['automations.notificationType.email', 'Email'],
  teams: ['automations.notificationType.teams', 'Microsoft Teams'],
  webhook: ['automations.notificationType.webhook', 'Webhook'],
}

// Delivery channels add the ticket systems to the notification channels.
const CHANNEL: Record<string, [string, string]> = {
  ...NOTIFICATION,
  jira: ['automations.channel.jira', 'Jira'],
  github: ['automations.channel.github', 'GitHub'],
}

const RISK: Record<string, [string, string]> = {
  low: ['automations.risk.low', 'Low'],
  elevated: ['automations.risk.elevated', 'Elevated'],
  high: ['automations.risk.high', 'High'],
}

const SKIP_REASON: Record<string, [string, string]> = {
  'refused:status_not_allowed': [
    'automations.skip.statusNotAllowed',
    'refused: status target not allowed',
  ],
  'refused:already_in_active_task': [
    'automations.skip.alreadyInActiveTask',
    'already in an active task',
  ],
  'refused:out_of_scope': ['automations.skip.outOfScope', 'outside the owner’s scope'],
  'refused:missing_permission': [
    'automations.skip.missingPermission',
    'owner lacks the permission',
  ],
  condition_false: ['automations.skip.conditionFalse', 'condition false'],
  cooldown: ['automations.skip.cooldown', 'cooldown'],
  held_daily_cap: ['automations.skip.heldDailyCap', 'held by the daily cap'],
  change_cap: ['automations.skip.changeCap', 'change cap reached'],
  duplicate: ['automations.skip.duplicate', 'duplicate'],
}

const VALIDATION: Record<string, [string, string]> = {
  UNSUPPORTED_TYPE: [
    'automations.validate.code.UNSUPPORTED_TYPE',
    'This step uses a type the platform no longer runs.',
  ],
  GRAPH_CYCLE: ['automations.validate.code.GRAPH_CYCLE', 'The steps form a loop; a run must end.'],
  GRAPH_UNREACHABLE: [
    'automations.validate.code.GRAPH_UNREACHABLE',
    'No trigger leads to this step, so it never runs.',
  ],
  CONDITION_INVALID: [
    'automations.validate.code.CONDITION_INVALID',
    'The condition cannot be read.',
  ],
  INTEGRATION_MISSING: [
    'automations.validate.code.INTEGRATION_MISSING',
    'The integration this step sends through does not exist.',
  ],
  OWNER_LACKS_PERMISSION: [
    'automations.validate.code.OWNER_LACKS_PERMISSION',
    'The owner of this automation lacks the permission this step needs.',
  ],
  STATUS_NOT_ALLOWED: [
    'automations.validate.code.STATUS_NOT_ALLOWED',
    'An automation may only set a finding to Confirmed or In progress.',
  ],
  CONFIG_MISSING: [
    'automations.validate.code.CONFIG_MISSING',
    'A required setting of this step is empty.',
  ],
  NO_SIMULATION_SINCE_EDIT: [
    'automations.validate.code.NO_SIMULATION_SINCE_EDIT',
    'Not simulated since the last edit.',
  ],
}

function pick(map: Record<string, [string, string]>, t: (k: string, f: string) => string) {
  return (value: string): string => {
    const e = Object.prototype.hasOwnProperty.call(map, value) ? map[value] : undefined
    return e ? t(e[0], e[1]) : value
  }
}

/** Translated names of automation types, risk classes, skip reasons and check codes. */
export function useAutomationLabels() {
  const { t } = useTranslation()
  return useMemo(() => {
    const trigger = pick(TRIGGER, t)
    const action = pick(ACTION, t)
    const notification = pick(NOTIFICATION, t)
    /** "action:http_request" -> "http_request": a removed type shows as its id. */
    const feature = (value: string): string =>
      value.includes(':') ? value.split(':', 2)[1] : value
    /** A validate problem or warning: the translated code, else the API's message. */
    const issue = (code: string, message: string): string => {
      const e = Object.prototype.hasOwnProperty.call(VALIDATION, code)
        ? VALIDATION[code]
        : undefined
      return e ? t(e[0], e[1]) : message || code
    }
    return {
      trigger,
      action,
      notification,
      channel: pick(CHANNEL, t),
      risk: pick(RISK, t),
      skipReason: pick(SKIP_REASON, t),
      feature,
      issue,
    }
  }, [t])
}
