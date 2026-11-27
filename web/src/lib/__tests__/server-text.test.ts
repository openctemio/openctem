import { describe, expect, it } from 'vitest'
import { translate, type Dictionary } from '@/lib/i18n'
import { en, vi } from '@/lib/i18n/dictionaries'
import {
  hasServerText,
  isServerMessage,
  messageOf,
  serverText,
  type Translate,
} from '@/lib/server-text'

function tr(dict: Dictionary, locale: string): Translate {
  return (key, fallback, vars) => translate(dict, key, fallback, vars, locale)
}

const dict: Dictionary = {
  'serverText.team.added.title': 'Added to team {team}',
  'serverText.team.added.body':
    '{count, plural, one {# seat} other {# seats}} as {role}, due {due_at}',
  'serverText.reason.held': 'held by {who}',
  'serverText.wrap.body': 'Because {reason}.',
  'serverText.digest.body': '{lines}',
  'org.role.admin': 'Admin',
  'assetCoverage.capability.capture.screenshot': 'Screenshots',
}
const t = tr(dict, 'en')

describe('serverText', () => {
  it('renders a code with counts, enums and times', () => {
    const m = {
      code: 'team.added',
      params: { team: 'Blue', count: 1200, role: 'admin', due_at: '2026-11-26T05:00:00Z' },
    }
    expect(serverText(t, 'en', m, 'fallback', 'title')).toBe('Added to team Blue')
    const body = serverText(t, 'en', m, 'fallback', 'body')
    expect(body).toMatch(/^1,200 seats as Admin, due Nov 26, 2026/)
  })

  it('falls back to the server text for no message, an unknown code, part or nested code', () => {
    expect(serverText(t, 'en', undefined, 'English')).toBe('English')
    expect(serverText(t, 'en', { code: 'not.known' }, 'English', 'title')).toBe('English')
    expect(serverText(t, 'en', { code: 'reason.held' }, 'English', 'title')).toBe('English')
    expect(
      serverText(
        t,
        'en',
        { code: 'wrap', params: { reason: { code: 'reason.nope' } } },
        'English',
        'body'
      )
    ).toBe('English')
    expect(serverText(t, 'en', { code: 'Bad Code' }, 'English')).toBe('English')
  })

  it('renders nested messages and digest lines', () => {
    const nested = {
      code: 'wrap',
      params: { reason: { code: 'reason.held', params: { who: 'Ann' } } },
    }
    expect(serverText(t, 'en', nested, 'x', 'body')).toBe('Because held by Ann.')
    const digest = {
      code: 'digest',
      params: { lines: [nested, { code: 'reason.held', params: { who: 'Bo' } }] },
    }
    expect(serverText(t, 'en', digest, 'x', 'body')).toBe('- Because held by Ann.\n- held by Bo')
    const badLine = { code: 'digest', params: { lines: [nested, 'text'] } }
    expect(serverText(t, 'en', badLine, 'x', 'body')).toBe('x')
  })

  it('keeps values as literal text: no placeholder or plural injection, controls made visible', () => {
    const m = {
      code: 'team.added',
      params: { team: '{count} {role} ‮evil', count: 2, role: 'admin' },
    }
    expect(serverText(t, 'en', m, 'x', 'title')).toBe('Added to team {count} {role} \\u{202E}evil')
    const plural = { code: 'reason.held', params: { who: '{n, plural, one {a} other {b}}' } }
    expect(serverText(t, 'en', plural, 'x')).toBe('held by {n, plural, one {a} other {b}}')
  })

  it('words a capability key and caps a long value', () => {
    const m = { code: 'reason.held', params: { who: 'x'.repeat(900) } }
    expect(serverText(t, 'en', m, 'f').length).toBeLessThan(520)
    const cap = { code: 'reason.held', params: { capability: 'capture.screenshot', who: 'A' } }
    expect(serverText(t, 'en', cap, 'f')).toBe('held by A')
  })

  it('joins a list of messages and words prefixed enums', () => {
    const d: Dictionary = {
      ...dict,
      'serverText.f.x': 'exposure',
      'serverText.f.y': 'criticality',
      'serverText.changed': 'Changed {fields} from {old_severity}',
      'severity.high': 'High',
    }
    const tt = tr(d, 'en')
    const m = {
      code: 'changed',
      params: { fields: [{ code: 'f.x' }, { code: 'f.y' }], old_severity: 'high' },
    }
    expect(serverText(tt, 'en', m, 'x')).toBe('Changed exposure, criticality from High')
    const bad = {
      code: 'changed',
      params: { fields: [{ code: 'f.x' }, 'raw'], old_severity: 'high' },
    }
    expect(serverText(tt, 'en', bad, 'x')).toBe('x')
  })

  it('recognises messages and payload fields', () => {
    expect(isServerMessage({ code: 'a.b' })).toBe(true)
    expect(isServerMessage({ code: 'A' })).toBe(false)
    expect(isServerMessage(['a'])).toBe(false)
    expect(messageOf('a.b', { n: 1 })).toEqual({ code: 'a.b', params: { n: 1 } })
    expect(messageOf('a.b', [1])).toEqual({ code: 'a.b', params: undefined })
    expect(messageOf('', {})).toBeUndefined()
    expect(hasServerText(t, 'en', { code: 'team.added' }, 'title')).toBe(true)
    expect(hasServerText(t, 'en', { code: 'team.added' })).toBe(false)
  })
})

describe('serverText catalog', () => {
  const keys = (d: Dictionary) => Object.keys(d).filter((k) => k.startsWith('serverText.'))

  it('has the same keys in en and vi', () => {
    expect(keys(vi).sort()).toEqual(keys(en).sort())
  })

  it('keeps the same placeholders in en and vi', () => {
    // Plural branch texts ("one {# asset}") are words, not placeholders.
    const PLURAL = /\{(\w+),\s*plural,((?:\s*(?:=\d+|\w+)\s*\{[^{}]*\})+)\s*\}/g
    const names = (s: string) =>
      [...new Set([...s.replace(PLURAL, '{$1}').matchAll(/\{(\w+)\}/g)].map((m) => m[1]))].sort()
    for (const k of keys(en)) expect([k, names(vi[k])]).toEqual([k, names(en[k])])
  })

  it('renders a coverage notice in Vietnamese without raw keys', () => {
    const m = {
      code: 'coverage.readiness',
      params: {
        capability: 'capture.screenshot',
        count: 3,
        readiness: { code: 'coverage.readiness.feature_off' },
        action: { code: 'coverage.action.feature_off' },
      },
    }
    const body = serverText(tr(vi, 'vi'), 'vi', m, 'English', 'body')
    expect(body).not.toBe('English')
    expect(body).not.toContain('capture.screenshot')
    expect(body).toContain('3 tài sản')
  })
})
