import { describe, expect, it } from 'vitest'

import { findingSourcesUrl } from '../sources-api'

describe('findingSourcesUrl', () => {
  it('reads /source-records, not /sources (which would shadow the removed analytics path)', () => {
    expect(findingSourcesUrl('a/b')).toBe('/api/v1/findings/a%2Fb/source-records')
  })
})

describe('source records ride in the finding view', () => {
  it('a primed view answers the records read without a request', async () => {
    const { primeView, takePrimed, clearPrimedViews } = await import('@/lib/api/view-prime')
    const url = findingSourcesUrl('019f5e75-08c4-7e03-8759-9d714faa29c3')
    const body = { data: [{ channel: 'sensor', primary: true }], differences: [] }
    primeView({ parts: { [url]: { status: 200, body } } })
    const res = takePrimed(url)
    expect(res?.status).toBe(200)
    expect(await res?.json()).toEqual(body)
    // Served once: a later read goes to the server.
    expect(takePrimed(url)).toBeUndefined()
    clearPrimedViews()
  })
})
