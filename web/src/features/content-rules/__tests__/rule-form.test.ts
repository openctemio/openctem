import { describe, expect, it } from 'vitest'

import { emptyForm, fromRule, parseHeaders, splitList, toRule } from '../lib/rule-form'

describe('rule form', () => {
  it('builds a fingerprint rule from the form and back', () => {
    const f = emptyForm('web-fingerprints')
    f.id = 'acme-portal'
    f.name = 'Acme portal'
    f.techName = 'Acme Portal'
    f.techCategory = 'framework'
    f.confidence = '80'
    f.matchers[0] = {
      location: 'header',
      header: 'Server',
      keywords: 'acme, portal',
      pattern: '(?i)^acme/(?P<version>\\d+)',
      hashes: '',
    }
    const rule = toRule(f)
    expect(rule).toEqual({
      id: 'acme-portal',
      name: 'Acme portal',
      technology: { name: 'Acme Portal', category: 'framework' },
      confidence: 80,
      matchers: [
        {
          location: 'header',
          header: 'server',
          keywords: ['acme', 'portal'],
          pattern: '(?i)^acme/(?P<version>\\d+)',
        },
      ],
    })
    expect(toRule(fromRule('web-fingerprints', rule))).toEqual(rule)
  })

  it('builds a secret rule and keeps only hashes on a favicon matcher', () => {
    const f = emptyForm('secret-rules')
    f.id = 'acme-key'
    f.name = 'Acme key'
    f.matchers[0].keywords = 'acme_'
    f.matchers[0].pattern = '\\bacme_[a-z0-9]{24}\\b'
    const rule = toRule(f)
    expect(rule.secret).toEqual({ category: 'token', severity: 'high' })
    expect(rule.technology).toBeUndefined()
    expect(rule.condition).toBeUndefined()

    const fp = emptyForm('web-fingerprints')
    fp.matchers[0] = {
      location: 'favicon',
      header: 'x',
      keywords: 'x',
      pattern: 'x',
      hashes: '1, -2',
    }
    expect(toRule(fp).matchers[0]).toEqual({ location: 'favicon', hashes: ['1', '-2'] })
  })

  it('splits lists and parses headers', () => {
    expect(splitList(' a, b\n\nc ,')).toEqual(['a', 'b', 'c'])
    expect(parseHeaders('Server: nginx/1.25\nX-Powered-By: PHP/8\nbad line')).toEqual({
      server: 'nginx/1.25',
      'x-powered-by': 'PHP/8',
    })
  })
})
