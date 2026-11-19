import { existsSync, readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

import en from '@/lib/i18n/dictionaries/en/auditLog.json'
import vi from '@/lib/i18n/dictionaries/vi/auditLog.json'

import { getActionLabel } from '../audit-types'

// Audit actions the console labels in the reader's language: a sensor, asset,
// sign-in or organization event must not read in English on a Vietnamese page.
const FAMILIES = new Set([
  'sensor',
  'sensor_result',
  'asset',
  'assets',
  'auth',
  'account',
  'api_key',
  'credential',
  'member',
  'role',
  'permission',
  'permission_set',
  'group',
  'user',
  'tenant',
  'sso',
  'finding',
  'scan_config',
  'scan_run',
])

const AUDIT_DIR = path.resolve(__dirname, '../../../../../server/pkg/domain/audit')

function serverActions(): string[] {
  const out = new Set<string>()
  for (const f of readdirSync(AUDIT_DIR)) {
    if (!f.endsWith('.go') || f.endsWith('_test.go')) continue
    const src = readFileSync(path.join(AUDIT_DIR, f), 'utf8')
    for (const m of src.matchAll(/\bAction\w*\s+Action\s*=\s*"([a-z_0-9]+\.[a-z_.0-9]+)"/g)) {
      out.add(m[1])
    }
  }
  return [...out].filter((a) => FAMILIES.has(a.split('.')[0])).sort()
}

const enCat = en as Record<string, string>
const viCat = vi as Record<string, string>

describe.skipIf(!existsSync(AUDIT_DIR))('audit action labels', () => {
  const actions = serverActions()

  it('finds the actions', () => {
    expect(actions.length).toBeGreaterThan(100)
  })

  it('every covered action has an en and a vi label, and vi differs from en', () => {
    const missing = actions.filter(
      (a) =>
        !enCat[`auditLog.action.${a}`] ||
        !viCat[`auditLog.action.${a}`] ||
        enCat[`auditLog.action.${a}`] === viCat[`auditLog.action.${a}`]
    )
    expect(missing).toEqual([])
  })

  it('the en label is the one the console shows without a catalog', () => {
    const differing = actions.filter((a) => enCat[`auditLog.action.${a}`] !== getActionLabel(a))
    expect(differing).toEqual([])
  })
})
