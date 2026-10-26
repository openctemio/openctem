// Tests for scripts/check-copy.mjs: each rule, and the strings it must leave alone.
import { describe, expect, it } from 'vitest'
import { checkValue } from './check-copy.mjs'

describe('checkValue', () => {
  it.each([
    ['Seamlessly connect your scanners', 'banned'],
    ['Leverage your data', 'banned'],
    ['Key revoked successfully', 'success'],
    ['Saved!', 'bang'],
    ['Not just a scanner, a platform', 'notjust'],
    ['EPSS — exploit prediction', 'emdash'],
    ['Open · 31', 'middot'],
    ['Request False Positive', 'titlecase'],
    ['Edit Suppression Rule', 'titlecase'],
    ['Show All {count} Lines', 'titlecase'],
  ])('%s breaks %s', (value, rule) => {
    expect(checkValue('x.key', value)).toContain(rule)
  })

  it.each([
    ['Key revoked.'],
    ['—'],
    ['Request a false positive'],
    ['Open in CISA KEV'],
    ['Connect Jira'],
    ['P0 and P1 findings'],
    ['CISA Known Exploited Vulnerability'],
    ['Settings, Roles'],
    ['e.g., Critical Finding Response'],
    ['Revealing the secret requires the Reveal Credential Secrets permission. Ask an admin.'],
    ['Mean time to remediate'],
  ])('%s is fine', (value) => {
    expect(checkValue('x.key', value)).toEqual([])
  })

  it('leaves the real security verbs alone', () => {
    expect(checkValue('admin.elevation.title', 'Elevate Your Access Now')).toEqual([])
  })
})
