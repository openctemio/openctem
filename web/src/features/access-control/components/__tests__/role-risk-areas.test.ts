import { describe, expect, it } from 'vitest'
import en from '@/lib/i18n/dictionaries/en/org.json'
import vi from '@/lib/i18n/dictionaries/vi/org.json'

/**
 * Every permission area the server summarises (the part of a permission
 * before ":") has a label in both languages, so a role's summary never shows
 * a raw identifier such as "Ai knowledge".
 */
const SERVER_AREAS = [
  'ai_knowledge',
  'ai_triage',
  'assets',
  'attack_surface',
  'audit',
  'automations',
  'compliance',
  'content',
  'ctem',
  'dashboard',
  'dashboards',
  'findings',
  'integrations',
  'pentest',
  'reports',
  'scans',
  'sensors',
  'service_accounts',
  'settings',
  'team',
  'threat_intel',
  'validation',
]

describe('role summary area labels', () => {
  it.each(SERVER_AREAS)('%s has an en and a vi label', (area) => {
    expect((en as Record<string, string>)[`org.roleArea.${area}`]).toBeTruthy()
    expect((vi as Record<string, string>)[`org.roleArea.${area}`]).toBeTruthy()
  })

  it('names the two dashboard areas apart', () => {
    const e = en as Record<string, string>
    expect(e['org.roleArea.dashboard']).not.toBe(e['org.roleArea.dashboards'])
  })
})
