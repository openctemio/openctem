/**
 * The mapping table <-> document round trip: a document loaded into the
 * editor and written back is the same document, members the table has no
 * control for included; and the table's own edits keep identity consistent.
 */
import { describe, expect, it } from 'vitest'
import {
  documentFromDraft,
  draftFromDocument,
  draftProblems,
  normalizeDocument,
  parseConstInput,
  renameTarget,
  rowsFromSet,
  setFromRows,
  toggleIdentity,
  withSource,
  withSourceKind,
} from '../lib/mapping-model'
import type { MappingDocument } from '../types/import-mapping.types'

const csvDoc: MappingDocument = {
  apiVersion: 'openctem.io/mapping/v1',
  source: 'csv',
  csv: { delimiter: ';', skip_rows: 2 },
  identity: ['title', 'asset_value'],
  records: [
    {
      kind: 'finding',
      set: {
        title: '/title',
        severity: {
          path: '/severity',
          trim: true,
          lower: true,
          map: { crit: 'critical', hi: 'high' },
          default: 'info',
        },
        asset_value: '/asset',
        tags: { path: '/tags', split: ',' },
        'vulnerability.cve_id': { path: '/CVE ID', upper: true, max_bytes: 64 },
      },
    },
    {
      kind: 'asset',
      set: {
        type: { const: 'host' },
        value: { template: '{h}:{p}', vars: { h: '/host', p: '/port' } },
      },
    },
  ],
}

const xmlDoc: MappingDocument = {
  apiVersion: 'openctem.io/mapping/v1',
  source: 'xml',
  each: '//testcase',
  notes: 'JUnit-style results',
  identity: ['rule_id'],
  records: [
    {
      when: [{ path: '/failure', exists: true }],
      kind: 'finding',
      set: {
        title: { path: '/@name', first: true },
        severity: { const: 'medium' },
        rule_id: { template: '{c}.{n}', vars: { c: '/@classname', n: '/@name' } },
        'location.start_line': { path: '/@line', as: 'integer' },
      },
    },
  ],
}

describe('document -> draft -> document', () => {
  it('keeps a CSV document with transforms, constants and templates', () => {
    expect(documentFromDraft(draftFromDocument(csvDoc))).toEqual(csvDoc)
  })

  it('keeps an XML document with conditions and notes', () => {
    expect(documentFromDraft(draftFromDocument(xmlDoc))).toEqual(xmlDoc)
  })

  it('writes a path-only value as the bare path', () => {
    const doc: MappingDocument = {
      apiVersion: 'openctem.io/mapping/v1',
      source: 'jsonl',
      identity: ['title'],
      records: [{ kind: 'finding', set: { title: { path: '/t' }, severity: '/s' } }],
    }
    expect(normalizeDocument(doc).records[0].set).toEqual({ title: '/t', severity: '/s' })
  })

  it('carries members it does not know, so the API can refuse them', () => {
    const doc = {
      ...xmlDoc,
      notez: 'typo',
      records: [{ ...xmlDoc.records[0], extra_rule: 1 }],
    } as unknown as MappingDocument
    const out = documentFromDraft(draftFromDocument(doc)) as unknown as Record<string, unknown>
    expect(out.notez).toBe('typo')
    expect((out.records as Record<string, unknown>[])[0].extra_rule).toBe(1)
  })

  it('keeps a foreign apiVersion for the API to refuse', () => {
    const doc = { ...csvDoc, apiVersion: 'openctem.io/mapping/v2' }
    expect(documentFromDraft(draftFromDocument(doc)).apiVersion).toBe('openctem.io/mapping/v2')
  })
})

describe('rows', () => {
  it('rows -> set keeps order and skips rows without a target', () => {
    const rows = rowsFromSet({ title: '/a', severity: { const: 'low' } })
    rows.push({ key: 'x', target: '', spec: { path: '/ignored' } })
    expect(Object.keys(setFromRows(rows))).toEqual(['title', 'severity'])
  })

  it('switching the source kind keeps the transforms', () => {
    expect(withSourceKind({ path: '/x', trim: true, default: 'n/a' }, 'const')).toEqual({
      const: '',
      trim: true,
      default: 'n/a',
    })
    expect(withSourceKind({ const: 'a', lower: true }, 'template')).toEqual({
      template: '',
      vars: {},
      lower: true,
    })
  })
})

describe('draft edits', () => {
  it('drops members the new source type does not allow', () => {
    const d = draftFromDocument(xmlDoc)
    const csv = documentFromDraft(withSource(d, 'csv'))
    expect(csv.each).toBeUndefined()
    expect(csv.csv).toEqual({ delimiter: 'auto' })
    const json = documentFromDraft(withSource(draftFromDocument(csvDoc), 'json'))
    expect(json.csv).toBeUndefined()
  })

  it('an identity member follows its row when the row is renamed', () => {
    const d = draftFromDocument(xmlDoc)
    const rule = d.rules[0]
    const row = rule.rows.find((r) => r.target === 'rule_id')!
    const renamed = renameTarget(d, rule.key, row.key, 'location.path')
    expect(renamed.identity).toEqual(['location.path'])
    // A target that cannot identify a finding leaves the identity list.
    const row2 = renamed.rules[0].rows.find((r) => r.target === 'location.path')!
    expect(renameTarget(renamed, rule.key, row2.key, 'description').identity).toEqual([])
  })

  it('toggles identity members', () => {
    const d = draftFromDocument(xmlDoc)
    expect(toggleIdentity(d, 'title', true).identity).toEqual(['rule_id', 'title'])
    expect(toggleIdentity(d, 'rule_id', false).identity).toEqual([])
  })

  it('reports missing identity, required members and duplicates', () => {
    const d = toggleIdentity(draftFromDocument(xmlDoc), 'rule_id', false)
    d.rules[0].rows = d.rules[0].rows.filter((r) => r.target !== 'severity')
    d.rules[0].rows.push({ key: 'dup', target: 'title', spec: { path: '/x' } })
    const codes = draftProblems(d).map((p) => p.code)
    expect(codes).toContain('identity_required')
    expect(codes).toContain('required')
    expect(codes).toContain('duplicate')
    expect(draftProblems(draftFromDocument(csvDoc))).toEqual([])
  })

  it('XML needs the record elements', () => {
    const d = { ...draftFromDocument(xmlDoc), each: undefined }
    expect(draftProblems(d).map((p) => p.code)).toContain('each_required')
  })
})

describe('constants typed by a person', () => {
  it('stays text unless the constant was not text', () => {
    expect(parseConstInput('5', 'x')).toBe('5')
    expect(parseConstInput('5', undefined)).toBe('5')
    expect(parseConstInput('7', 3)).toBe(7)
    expect(parseConstInput('["a","b"]', ['z'])).toEqual(['a', 'b'])
    expect(parseConstInput('not json', true)).toBe('not json')
  })
})
