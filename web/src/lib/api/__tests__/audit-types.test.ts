import { describe, expect, it } from 'vitest'

import {
  canonicalAuditAction,
  canonicalAuditMetadataKey,
  canonicalAuditResourceType,
  getActionLabel,
  SENSOR_AUDIT_VERBS,
} from '../audit-types'
import { formatAction } from '@/features/organization/types/audit.types'

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

  it('labels sensor.created as "Sensor Created" on the settings audit page', () => {
    expect(formatAction('sensor.created')).toBe('Sensor Created')
    expect(formatAction('agent.created')).toBe('Sensor Created')
    expect(formatAction('agent.key_regenerated')).toBe('Sensor Key Regenerated')
  })

  it('labels sensor.commands_released (jobs taken back on revoke/disable, RFC-040)', () => {
    expect(getActionLabel('sensor.commands_released')).toBe(
      'Sensor Jobs Taken Back (Revoked or Disabled)'
    )
    expect(formatAction('sensor.commands_released')).toBe('Sensor Commands Released')
  })

  it('labels the scan zone actions (RFC-023)', () => {
    expect(getActionLabel('scan_zone.created')).toBe('Scan Zone Created')
    expect(getActionLabel('scan_zone.sensor_assigned')).toBe('Sensor Assigned to Scan Zone')
    expect(getActionLabel('scan_zone.sensor_unassigned')).toBe('Sensor Unassigned from Scan Zone')
    expect(canonicalAuditResourceType('scan_zone')).toBe('scan_zone')
  })

  it('labels the scope, tool and scanner template changes (RFC-040)', () => {
    expect(getActionLabel('scope_target.created')).toBe('Scope Target Created')
    expect(getActionLabel('scope_exclusion.deactivated')).toBe('Scope Exclusion Deactivated')
    expect(getActionLabel('tool.config_updated')).toBe('Tool Configuration Updated')
    expect(getActionLabel('scanner_template.updated')).toBe('Scanner Template Updated')
    expect(canonicalAuditResourceType('scope_exclusion')).toBe('scope_exclusion')
  })

  it('labels the remediation campaign actions', () => {
    expect(getActionLabel('remediation_campaign.created')).toBe('Remediation Campaign Created')
    expect(getActionLabel('remediation_campaign.updated')).toBe('Remediation Campaign Updated')
    expect(getActionLabel('remediation_campaign.status_changed')).toBe(
      'Remediation Campaign Status Changed'
    )
    expect(getActionLabel('remediation_campaign.deleted')).toBe('Remediation Campaign Deleted')
    expect(canonicalAuditResourceType('remediation_campaign')).toBe('remediation_campaign')
  })

  it('leaves every other action alone', () => {
    expect(canonicalAuditAction('finding.created')).toBe('finding.created')
    expect(canonicalAuditAction('user_agent.created')).toBe('user_agent.created')
    expect(getActionLabel('finding.created')).toBe('Finding Created')
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
