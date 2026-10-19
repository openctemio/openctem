'use client'

import { useMemo } from 'react'

import { useTranslation } from '@/context/i18n-provider'
import type {
  WorkflowActionType,
  WorkflowNotificationType,
  WorkflowTriggerType,
} from '@/lib/api/workflow-types'

// Static keys per type (never built from a template string) so the key
// checker and a grep can find every one. Each entry is [key, English].
const TRIGGER: Record<WorkflowTriggerType, [string, string]> = {
  manual: ['automations.triggerType.manual', 'Manual'],
  schedule: ['automations.triggerType.schedule', 'Scheduled'],
  finding_created: ['automations.triggerType.finding_created', 'Finding Created'],
  finding_updated: ['automations.triggerType.finding_updated', 'Finding Updated'],
  finding_age: ['automations.triggerType.finding_age', 'Finding Age'],
  asset_discovered: ['automations.triggerType.asset_discovered', 'Asset Discovered'],
  scan_completed: ['automations.triggerType.scan_completed', 'Scan Completed'],
  webhook: ['automations.triggerType.webhook', 'Webhook'],
  finding_status_changed: [
    'automations.triggerType.finding_status_changed',
    'Finding Status Changed',
  ],
}

const ACTION: Record<WorkflowActionType, [string, string]> = {
  assign_user: ['automations.actionType.assign_user', 'Assign User'],
  assign_team: ['automations.actionType.assign_team', 'Assign Team'],
  update_priority: ['automations.actionType.update_priority', 'Update Priority'],
  update_status: ['automations.actionType.update_status', 'Update Status'],
  add_tags: ['automations.actionType.add_tags', 'Add Tags'],
  remove_tags: ['automations.actionType.remove_tags', 'Remove Tags'],
  create_ticket: ['automations.actionType.create_ticket', 'Create Ticket'],
  update_ticket: ['automations.actionType.update_ticket', 'Update Ticket'],
  trigger_pipeline: ['automations.actionType.trigger_pipeline', 'Trigger Pipeline'],
  trigger_scan: ['automations.actionType.trigger_scan', 'Trigger Scan'],
  http_request: ['automations.actionType.http_request', 'HTTP Request'],
  run_script: ['automations.actionType.run_script', 'Run Script'],
}

const NOTIFICATION: Record<WorkflowNotificationType, [string, string]> = {
  slack: ['automations.notificationType.slack', 'Slack'],
  email: ['automations.notificationType.email', 'Email'],
  teams: ['automations.notificationType.teams', 'Microsoft Teams'],
  webhook: ['automations.notificationType.webhook', 'Webhook'],
  pagerduty: ['automations.notificationType.pagerduty', 'PagerDuty'],
}

/** Translated names of workflow trigger, action and notification types. */
export function useAutomationLabels() {
  const { t } = useTranslation()
  return useMemo(() => {
    // An unknown type (a newer API value) shows as it is.
    const trigger = (type: string): string => {
      const e = (TRIGGER as Record<string, [string, string] | undefined>)[type]
      return e ? t(e[0], e[1]) : type
    }
    const action = (type: string): string => {
      const e = (ACTION as Record<string, [string, string] | undefined>)[type]
      return e ? t(e[0], e[1]) : type
    }
    const notification = (type: string): string => {
      const e = (NOTIFICATION as Record<string, [string, string] | undefined>)[type]
      return e ? t(e[0], e[1]) : type
    }
    /** "action:assign_team" -> "Assign Team action". Unknown values pass through. */
    const feature = (value: string): string => {
      const [kind, type = ''] = value.split(':', 2)
      if (kind === 'trigger' && type in TRIGGER) {
        return t('automations.feature.trigger', '{label} trigger', { label: trigger(type) })
      }
      if (kind === 'action' && type in ACTION) {
        return t('automations.feature.action', '{label} action', { label: action(type) })
      }
      return value
    }
    return { trigger, action, notification, feature }
  }, [t])
}
