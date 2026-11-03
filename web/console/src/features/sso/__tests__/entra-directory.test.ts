import { describe, expect, it } from 'vitest'

import { entraNeedsDirectoryId, isEntraDirectoryId } from '../lib/entra-directory'

describe('entra directory id', () => {
  it('accepts the directory GUID', () => {
    expect(isEntraDirectoryId('aaaaaaaa-1111-2222-3333-444444444444')).toBe(true)
    expect(entraNeedsDirectoryId('entra_id', 'AAAAAAAA-1111-2222-3333-444444444444')).toBe(false)
  })

  it.each(['', 'common', 'organizations', 'consumers', 'contoso.onmicrosoft.com', undefined, null])(
    'flags an Entra provider saved as %j',
    (value) => {
      expect(entraNeedsDirectoryId('entra_id', value)).toBe(true)
    }
  )

  it('never flags another provider', () => {
    expect(entraNeedsDirectoryId('okta', 'https://dev-1.okta.com')).toBe(false)
  })
})
