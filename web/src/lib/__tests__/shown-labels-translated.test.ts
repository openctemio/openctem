/**
 * Guard: labels built from data (audit action names, asset type names, the
 * sign-in method) read in the reader's language. Each helper takes `t` and
 * looks up a catalog key; this test fails when a known value has no English
 * or no Vietnamese entry, so a Vietnamese page never shows "Invitation
 * created", "Web application" or "Email and password". It also keeps one
 * Vietnamese wording for the same short English label ("Needs attention").
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { getActionLabel } from '@/lib/api/audit-types'
import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { ASSET_TYPE_LABELS } from '@/features/assets/types/asset.types'
import { identityProviderLabel } from '@/lib/identity-provider-label'

const DICT = join(process.cwd(), 'src', 'lib', 'i18n', 'dictionaries')

function catalog(locale: 'en' | 'vi'): Record<string, string> {
  const out: Record<string, string> = {}
  for (const f of readdirSync(join(DICT, locale)).filter((n) => n.endsWith('.json'))) {
    Object.assign(out, JSON.parse(readFileSync(join(DICT, locale, f), 'utf8')))
  }
  return out
}

const en = catalog('en')
const vi = catalog('vi')
const AUDIT_SRC = readFileSync(join(process.cwd(), 'src', 'lib', 'api', 'audit-types.ts'), 'utf8')

/** Every action the console knows: the AuditAction union and the label overrides. */
function knownActions(): string[] {
  const union = AUDIT_SRC.slice(AUDIT_SRC.indexOf('export type AuditAction ='))
  const body = union.slice(0, union.indexOf('\n\n'))
  const fromUnion = [...body.matchAll(/\|\s*'([a-z0-9_.]+)'/g)].map((m) => m[1])
  const fromOverrides = [...AUDIT_SRC.matchAll(/^\s+'([a-z0-9_.]+)': '[^']*',$/gm)].map((m) => m[1])
  return [...new Set([...fromUnion, ...fromOverrides])]
}

/** A `t` over one catalog that records the keys it was asked for. */
function recorder(dict: Record<string, string>) {
  const missing: string[] = []
  const t = (key: string, fallback: string) => {
    if (dict[key] === undefined) missing.push(key)
    return dict[key] ?? fallback
  }
  return { t, missing }
}

describe('labels shown from data are translated', () => {
  it('names every known audit action in en and vi', () => {
    const actions = knownActions()
    expect(actions.length).toBeGreaterThan(100)
    for (const dict of [en, vi]) {
      const { t, missing } = recorder(dict)
      for (const a of actions) getActionLabel(a, t)
      expect(missing).toEqual([])
    }
    const { t } = recorder(vi)
    expect(getActionLabel('invitation.created', t)).not.toBe('Invitation created')
  })

  it('names every asset type in en and vi', () => {
    for (const dict of [en, vi]) {
      const { t, missing } = recorder(dict)
      for (const type of Object.keys(ASSET_TYPE_LABELS)) getAssetTypeLabel(type, t)
      getAssetTypeLabel(undefined, t)
      expect(missing).toEqual([])
    }
  })

  it('names the password sign-in method in the reader language', () => {
    const { t, missing } = recorder(vi)
    expect(identityProviderLabel('local', t)).not.toBe('Email and password')
    expect(identityProviderLabel(null, t)).toBe(identityProviderLabel('local', t))
    // Product names stay as they are.
    expect(identityProviderLabel('google_workspace', t)).toBe('Google Workspace')
    expect(missing).toEqual([])
  })

  it('gives "Needs attention" one Vietnamese wording', () => {
    const words = new Set(
      Object.entries(en)
        .filter(([, v]) => v === 'Needs attention')
        .map(([k]) => vi[k])
        .filter(Boolean)
    )
    expect([...words]).toEqual(['Cần chú ý'])
  })
})
