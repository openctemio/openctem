import { existsSync, readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

import en from '@/lib/i18n/dictionaries/en/auditLog.json'
import vi from '@/lib/i18n/dictionaries/vi/auditLog.json'

// Every resource type the server writes into the audit log has a label in
// both languages: the Resource column of a Vietnamese audit log must not read
// "Verified domain" (acceptance 2026-11-21).

const AUDIT_DIR = path.resolve(__dirname, '../../../../../server/pkg/domain/audit')

function serverResourceTypes(): string[] {
  const out = new Set<string>()
  for (const f of readdirSync(AUDIT_DIR)) {
    if (!f.endsWith('.go') || f.endsWith('_test.go')) continue
    const src = readFileSync(path.join(AUDIT_DIR, f), 'utf8')
    for (const m of src.matchAll(/\bResourceType\w*\s+ResourceType\s*=\s*"([a-z_0-9]+)"/g)) {
      out.add(m[1])
    }
  }
  return [...out].sort()
}

const enCat = en as Record<string, string>
const viCat = vi as Record<string, string>

describe.skipIf(!existsSync(AUDIT_DIR))('audit resource type labels', () => {
  const types = serverResourceTypes()

  it('finds the resource types', () => {
    expect(types.length).toBeGreaterThan(100)
  })

  it('every resource type has an en and a vi label', () => {
    const missing = types.filter(
      (r) => !enCat[`auditLog.resourceType.${r}`] || !viCat[`auditLog.resourceType.${r}`]
    )
    expect(missing).toEqual([])
  })
})
