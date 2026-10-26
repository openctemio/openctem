import { describe, expect, it } from 'vitest'
import {
  documentToDraft,
  draftToDocument,
  EMPTY_RULE_DRAFT,
  filterParamsToRule,
  invalidDomains,
  isDomainLine,
  isDraftEmpty,
  isRuleEmpty,
  parseDomains,
} from '../group-rule'
import { countPasteLines, MAX_PASTE_LINES } from '../group-paste'

describe('domains of a rule', () => {
  it('reads one domain per line, comma or space, without repeats', () => {
    expect(parseDomains('a.example.com\n*.b.example.com, A.EXAMPLE.com  c.example.org')).toEqual([
      'a.example.com',
      '*.b.example.com',
      'c.example.org',
    ])
  })

  it('accepts names and wildcards, refuses what is not a DNS name', () => {
    for (const ok of ['example.com', '*.example.com', 'Sub.Example.com.', 'bücher.de']) {
      expect(isDomainLine(ok), ok).toBe(true)
    }
    for (const bad of [
      'example',
      'http://example.com',
      'example.com/path',
      'example.com:443',
      '10.0.0.1',
      'a*.example.com',
      '*',
      'user@example.com',
      '',
    ]) {
      expect(isDomainLine(bad), bad).toBe(false)
    }
    expect(
      invalidDomains({ ...EMPTY_RULE_DRAFT, domainsText: 'ok.example.com\nhttp://bad' })
    ).toEqual(['http://bad'])
  })
})

describe('rule draft and document', () => {
  it('an empty draft has no condition and a filled one does', () => {
    expect(isDraftEmpty(EMPTY_RULE_DRAFT)).toBe(true)
    expect(isDraftEmpty({ ...EMPTY_RULE_DRAFT, tags: ['prod'] })).toBe(false)
    expect(isDraftEmpty({ ...EMPTY_RULE_DRAFT, internetFacing: true })).toBe(false)
    expect(isDraftEmpty({ ...EMPTY_RULE_DRAFT, includeRelated: true })).toBe(true)
  })

  it('builds the document the API takes and reads it back', () => {
    const doc = draftToDocument({
      ...EMPTY_RULE_DRAFT,
      domainsText: 'pti.com.vn\n*.vndirect.com.vn',
      subdomains: true,
      types: ['domain'],
      tags: ['prod'],
      internetFacing: true,
      search: ' www ',
      includeRelated: true,
      coveredBy: ['11111111-1111-1111-1111-111111111111'],
    })
    expect(doc).toEqual({
      v: 1,
      filter: { types: ['domain'], tags: ['prod'], internet_facing: true, search: 'www' },
      domains: [
        { name: 'pti.com.vn', subdomains: true },
        { name: '*.vndirect.com.vn', subdomains: true },
      ],
      covered_by: ['11111111-1111-1111-1111-111111111111'],
      include_related: true,
    })
    const draft = documentToDraft(doc)
    expect(draft.domainsText).toBe('pti.com.vn\n*.vndirect.com.vn')
    expect(draftToDocument(draft)).toEqual(doc)
  })

  it('keeps the filter fields the editor cannot show', () => {
    const doc = {
      v: 1 as const,
      filter: { types: ['host'], min_risk_score: 70, attribution: ['confirmed'] },
    }
    const draft = documentToDraft(doc)
    expect(draft.extra).toEqual({ min_risk_score: 70, attribution: ['confirmed'] })
    expect(draftToDocument(draft).filter).toEqual(doc.filter)
  })

  it('no subdomains: a plain domain stays exact', () => {
    const doc = draftToDocument({
      ...EMPTY_RULE_DRAFT,
      domainsText: 'pti.com.vn',
      subdomains: false,
    })
    expect(doc.domains).toEqual([{ name: 'pti.com.vn', subdomains: false }])
  })
})

describe('the Assets list filter as a rule', () => {
  it('maps the list parameters by name and type', () => {
    const { rule, unsupported } = filterParamsToRule({
      types: 'domain,host',
      tags: 'prod,edge',
      tags_mode: 'all',
      min_risk_score: '70',
      has_findings: 'true',
      internet_facing: 'false',
      search: 'pti',
      attribution: 'confirmed,discovered',
      page: '3',
      per_page: '50',
      sort: '-created_at',
      with_triage: 'true',
    })
    expect(unsupported).toEqual([])
    expect(rule).toEqual({
      v: 1,
      filter: {
        types: ['domain', 'host'],
        tags: ['prod', 'edge'],
        tags_mode: 'all',
        min_risk_score: 70,
        has_findings: true,
        internet_facing: false,
        search: 'pti',
        attribution: ['confirmed', 'discovered'],
      },
    })
    expect(isRuleEmpty(rule)).toBe(false)
  })

  it('names the parameters a rule cannot hold instead of dropping them silently', () => {
    const { rule, unsupported } = filterParamsToRule({
      types: 'domain',
      last_seen_after: '2026-10-01',
      discovered_by: 'tenant_scanned',
      properties: 'port:443',
    })
    expect(unsupported.sort()).toEqual(['discovered_by', 'last_seen_after', 'properties'])
    expect(rule.filter).toEqual({ types: ['domain'] })
  })

  it('page-only parameters make an empty rule', () => {
    expect(isRuleEmpty(filterParamsToRule({ page: '1', per_page: '20', sort: 'name' }).rule)).toBe(
      true
    )
  })

  it('ignores a number or boolean that is not one', () => {
    const { rule } = filterParamsToRule({ min_risk_score: 'x', has_owner: 'maybe', types: ' , ' })
    expect(rule.filter).toEqual({})
  })
})

describe('pasted list size', () => {
  it('counts the lines the API counts', () => {
    expect(countPasteLines('')).toBe(0)
    expect(countPasteLines('a.example.com\n\n# note\n  b.example.com  \n')).toBe(2)
    expect(countPasteLines('x\n'.repeat(MAX_PASTE_LINES + 1))).toBe(MAX_PASTE_LINES + 1)
  })
})
