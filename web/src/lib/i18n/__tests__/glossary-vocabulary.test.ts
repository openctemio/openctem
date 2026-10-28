import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Glossary vocabulary guard (glossary: api/docs/glossary.md).
 *
 * One concept has one name in the console text. This fails on a retired word in
 * any en or vi dictionary value and names the term to use. To allow a hit, add
 * the key to the rule's allowKeys with the reason (an external product's own
 * word, for example); do not weaken a pattern.
 */

const DICT = join(__dirname, '..', 'dictionaries')

type Lang = 'en' | 'vi'
interface Rule {
  lang: Lang
  pattern: RegExp
  use: string
  allowKeys: { key: string; why: string }[]
  /** One sample the pattern must catch and one it must spare (self-test). */
  catches: string
  spares: string
}

const RULES: Rule[] = [
  {
    lang: 'en',
    pattern: /\btenants?\b/i,
    use: 'organization',
    allowKeys: [
      {
        key: 'admin.identityProvidersPanel.directoryTenantId',
        why: 'the Azure/Entra field is named Directory (Tenant) ID',
      },
      {
        key: 'admin.internalZones.recommend',
        why: 'multi-tenant is the deployment model of a public cloud, not our organization',
      },
      {
        key: 'admin.proof.recommend',
        why: 'multi-tenant is the deployment model of a public cloud, not our organization',
      },
      {
        key: 'scans.ci.refusal.legacy_audienceFix',
        why: 'quotes the literal audience string openctem:tenant:<id> that old CI snippets send',
      },
    ],
    catches: 'Track a new group for this tenant.',
    spares: 'Track a new group for this organization.',
  },
  {
    lang: 'en',
    pattern: /\borganis(e|ation)/i,
    use: 'the American spelling: organization, organize',
    allowKeys: [],
    catches: 'Tied to your organisation',
    spares: 'Tied to your organization',
  },
  {
    lang: 'en',
    pattern: /\bworkspaces?\b/i,
    use: 'organization',
    allowKeys: [
      {
        key: 'admin.identityProvidersPanel.workspaceDomain',
        why: 'the Google Workspace domain field',
      },
      {
        key: 'scans.ci.refusal.organization_mismatchFix',
        why: 'Bitbucket calls a repository owner a workspace',
      },
      { key: 'scans.ci.setup.workspace', why: 'Bitbucket workspace field' },
      { key: 'scans.ci.trust.ownersBitbucket', why: 'Bitbucket workspace owners' },
      { key: 'scans.ci.trust.workspace', why: 'Bitbucket workspace field' },
      { key: 'scans.ci.trust.workspaceHint', why: 'Bitbucket workspace in the repository URL' },
      { key: 'scans.ci.trust.workspaceUuid', why: 'Bitbucket workspace UUID field' },
      { key: 'scans.ci.trust.workspaceUuidHint', why: 'Bitbucket workspace UUID' },
    ],
    catches: 'None in this workspace yet.',
    spares: 'None in this organization yet.',
  },
  {
    lang: 'en',
    pattern: /\bAI analysts?\b/i,
    use: 'AI agent (with the analyst role)',
    allowKeys: [],
    catches: 'The AI analyst reviews it',
    spares: 'The AI agent with the analyst role reviews it',
  },
  {
    lang: 'vi',
    pattern: /cảm biến/i,
    use: 'sensor',
    allowKeys: [],
    catches: 'Đã tạo cảm biến',
    spares: 'Đã tạo sensor',
  },
  {
    lang: 'vi',
    pattern: /lượt chạy/i,
    use: 'lần chạy',
    allowKeys: [],
    catches: 'Lượt chạy gần đây',
    spares: 'Lần chạy gần đây',
  },
  {
    lang: 'vi',
    pattern: /nhật ký kiểm tra/i,
    use: 'nhật ký kiểm toán',
    allowKeys: [],
    catches: 'Nhật ký kiểm tra',
    spares: 'Nhật ký kiểm toán',
  },
]

function load(lang: Lang): Record<string, string> {
  const out: Record<string, string> = {}
  const dir = join(DICT, lang)
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.json'))) {
    const j = JSON.parse(readFileSync(join(dir, f), 'utf8')) as Record<string, unknown>
    for (const [k, v] of Object.entries(j)) if (typeof v === 'string') out[k] = v
  }
  return out
}

const DICTS: Record<Lang, Record<string, string>> = { en: load('en'), vi: load('vi') }

describe('glossary vocabulary (api/docs/glossary.md)', () => {
  for (const r of RULES) {
    it(`${r.lang}: no ${r.pattern} (use ${r.use})`, () => {
      const allowed = new Set(r.allowKeys.map((a) => a.key))
      const hits = Object.entries(DICTS[r.lang])
        .filter(([k, v]) => r.pattern.test(v) && !allowed.has(k))
        .map(([k, v]) => `  ${k}: ${v}`)
      expect(
        hits,
        `${r.lang} text uses a retired word. The glossary (api/docs/glossary.md) says to use "${r.use}":\n${hits.join('\n')}`
      ).toEqual([])
    })

    it(`${r.lang}: ${r.pattern} self-test`, () => {
      expect(r.pattern.test(r.catches)).toBe(true)
      expect(r.pattern.test(r.spares)).toBe(false)
    })

    it(`${r.lang}: ${r.pattern} allow list names real keys with a reason`, () => {
      for (const a of r.allowKeys) {
        expect(a.why.length, a.key).toBeGreaterThan(5)
        expect(DICTS[r.lang][a.key], `${a.key} is not a ${r.lang} key`).toBeDefined()
        expect(r.pattern.test(DICTS[r.lang][a.key]), `${a.key} no longer matches`).toBe(true)
      }
    })
  }
})
