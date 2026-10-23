import { describe, expect, it } from 'vitest'

import { assetSlaPolicyUrl } from '../use-sla-policies-api'

describe('assetSlaPolicyUrl', () => {
  it('has no trailing slash, so the read is not redirected first', () => {
    expect(assetSlaPolicyUrl('a1')).toBe('/api/v1/assets/a1/sla-policy')
  })

  it('encodes the asset id', () => {
    expect(assetSlaPolicyUrl('a/b')).toBe('/api/v1/assets/a%2Fb/sla-policy')
  })
})
