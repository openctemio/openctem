import { describe, expect, it } from 'vitest'
import { humanizeIdentifier, identifierWord } from '../humanize-identifier'

describe('humanizeIdentifier', () => {
  it.each([
    ['sso.change_requested', 'SSO change requested'],
    ['idp_create', 'Identity provider create'],
    ['tenant.created', 'Organization created'],
    ['scan_zone.sensor_assigned', 'Scan zone sensor assigned'],
    ['google-workspace', 'Google workspace'],
    ['API_KEY', 'API key'],
  ])('%s -> %s', (id, label) => {
    expect(humanizeIdentifier(id)).toBe(label)
  })

  it('returns an empty label for an empty identifier', () => {
    expect(humanizeIdentifier('')).toBe('')
  })

  it('keeps acronyms upper case mid-sentence', () => {
    expect(identifierWord('saml')).toBe('SAML')
    expect(identifierWord('Finding')).toBe('finding')
  })
})
