import { describe, expect, it } from 'vitest'

import {
  canonicalAuditAction,
  canonicalAuditMetadataKey,
  canonicalAuditResourceType,
  getActionLabel,
  SENSOR_AUDIT_VERBS,
} from '../audit-types'
import { formatAction } from '@/features/organization/types/audit.types'
import fs from 'node:fs'
import path from 'node:path'

/**
 * Audit rows written before the agent -> sensor rename keep agent.*, resource
 * type "agent" and agent_* metadata forever (hash-chained). The API returns
 * them as written, so the UI must label both spellings the same way.
 */
describe('sensor audit events before and after the rename', () => {
  it.each(SENSOR_AUDIT_VERBS)('labels agent.%s like sensor.%s', (verb) => {
    const historical = `agent.${verb}` as const
    const current = `sensor.${verb}` as const
    expect(canonicalAuditAction(historical)).toBe(current)
    expect(getActionLabel(historical)).toBe(getActionLabel(current))
    expect(getActionLabel(current)).not.toBe(current)
    expect(getActionLabel(current)).toMatch(/^Sensor /)
    expect(formatAction(historical)).toBe(formatAction(current))
  })

  it('labels sensor.created as "Sensor created" on the settings audit page', () => {
    expect(formatAction('sensor.created')).toBe('Sensor created')
    expect(formatAction('agent.created')).toBe('Sensor created')
    expect(formatAction('agent.key_regenerated')).toBe('Sensor API key regenerated')
  })

  it('labels sensor.commands_released (jobs taken back on revoke/disable, RFC-040)', () => {
    expect(getActionLabel('sensor.commands_released')).toBe(
      'Sensor jobs taken back (revoked or disabled)'
    )
    expect(formatAction('sensor.commands_released')).toBe(
      getActionLabel('sensor.commands_released')
    )
  })

  it('labels the scan zone actions (RFC-023)', () => {
    expect(getActionLabel('scan_zone.created')).toBe('Scan zone created')
    expect(getActionLabel('scan_zone.sensor_assigned')).toBe('Sensor assigned to scan zone')
    expect(getActionLabel('scan_zone.sensor_unassigned')).toBe('Sensor unassigned from scan zone')
    expect(canonicalAuditResourceType('scan_zone')).toBe('scan_zone')
  })

  it('labels the scope, tool and scanner template changes (RFC-040)', () => {
    expect(getActionLabel('scope_target.created')).toBe('Scope target created')
    expect(getActionLabel('scope_exclusion.deactivated')).toBe('Scope exclusion deactivated')
    expect(getActionLabel('tool.config_updated')).toBe('Tool configuration updated')
    expect(getActionLabel('scanner_template.updated')).toBe('Scanner template updated')
    expect(canonicalAuditResourceType('scope_exclusion')).toBe('scope_exclusion')
  })

  it('labels the remediation campaign actions', () => {
    expect(getActionLabel('remediation_campaign.created')).toBe('Remediation campaign created')
    expect(getActionLabel('remediation_campaign.updated')).toBe('Remediation campaign updated')
    expect(getActionLabel('remediation_campaign.status_changed')).toBe(
      'Remediation campaign status changed'
    )
    expect(getActionLabel('remediation_campaign.deleted')).toBe('Remediation campaign deleted')
    expect(canonicalAuditResourceType('remediation_campaign')).toBe('remediation_campaign')
  })

  it('leaves every other action alone', () => {
    expect(canonicalAuditAction('finding.created')).toBe('finding.created')
    expect(canonicalAuditAction('user_agent.created')).toBe('user_agent.created')
    expect(getActionLabel('finding.created')).toBe('Finding created')
  })

  it('maps the resource type "agent" onto "sensor" and nothing else', () => {
    expect(canonicalAuditResourceType('agent')).toBe('sensor')
    expect(canonicalAuditResourceType('sensor')).toBe('sensor')
    expect(canonicalAuditResourceType('finding')).toBe('finding')
  })

  it('maps the pre-rename metadata keys onto sensor_*', () => {
    expect(canonicalAuditMetadataKey('agent_type')).toBe('sensor_type')
    expect(canonicalAuditMetadataKey('agent_id')).toBe('sensor_id')
    expect(canonicalAuditMetadataKey('agent_name')).toBe('sensor_name')
    expect(canonicalAuditMetadataKey('sensor_id')).toBe('sensor_id')
    // Only the three keys the contract names; an unrelated key is not touched.
    expect(canonicalAuditMetadataKey('agent_version')).toBe('agent_version')
    expect(canonicalAuditMetadataKey('user_agent')).toBe('user_agent')
  })
})

/**
 * Every view labels an action through getActionLabel. The settings audit log
 * used to Title-Case the raw id instead ("Sso Change Requested").
 */
describe('audit action labels', () => {
  it('reads acronyms and product terms the console way', () => {
    expect(getActionLabel('sso.change_requested')).toBe('SSO change requested')
    expect(formatAction('sso.change_requested')).toBe('SSO change requested')
    expect(getActionLabel('tenant.settings_updated')).toBe('Organization settings updated')
    expect(getActionLabel('user.mfa_enabled')).toBe('User two-step verification enabled')
    expect(getActionLabel('api_key.created')).toBe('API key created')
  })

  // Every action the API can write (api/pkg/domain/audit/value_objects.go)
  // gets a sentence-case label, never the raw id.
  const source = fs.readFileSync(
    path.resolve(__dirname, '../../../../../api/pkg/domain/audit/value_objects.go'),
    'utf8'
  )
  const apiActions = [...source.matchAll(/^\s+Action\w+\s+Action\s*=\s*"([a-z0-9_.]+)"/gm)].map(
    (m) => m[1]
  )

  it('finds the API action list', () => {
    expect(apiActions.length).toBeGreaterThan(100)
    expect(apiActions).toContain('sso.change_requested')
  })

  it('labels every API action in sentence case, without raw separators', () => {
    for (const action of apiActions) {
      const label = getActionLabel(action)
      expect(label, action).not.toMatch(/[._]/)
      expect(label.charAt(0), action).toBe(label.charAt(0).toUpperCase())
      // No Title Case: after the first word, a capital starts only an acronym.
      for (const word of label.split(' ').slice(1)) {
        if (/^[A-Z][a-z]/.test(word)) throw new Error(`${action}: "${label}"`)
      }
      expect(formatAction(action), action).toBe(label)
    }
  })
})
