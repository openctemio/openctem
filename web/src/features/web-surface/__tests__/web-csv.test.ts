import { describe, expect, it } from 'vitest'
import type { WebEndpointEventResponse, WebEndpointResponse } from '@/lib/api/generated'
import { endpointsCsv, eventsCsv, paramsCsv } from '../lib/web-csv'

const lines = (csv: string) => csv.split('\n')

describe('CSV export escapes formulas', () => {
  it.each(['=1+1', '+SUM(A1)', '-2+3', '@cmd', '\t=x', '\r=x'])(
    'prefixes a cell starting with %j',
    (value) => {
      const ep = { method: 'GET', path_template: value } as WebEndpointResponse
      const row = lines(endpointsCsv([ep], ['a', 'b', 'c', 'd', 'e', 'f', 'g']))[1]
      expect(row).toContain(`'${value}`)
    }
  )

  it('guards events and parameters too, and quotes commas', () => {
    const ev = {
      at: 't',
      kind: 'appeared',
      method: 'GET',
      path_template: '=HYPERLINK("http://x")',
    } as WebEndpointEventResponse
    const evRow = lines(eventsCsv([ev], ['a', 'b', 'c', 'd', 'e']))[1]
    expect(evRow).toContain(`"'=HYPERLINK(""http://x"")"`)
    const pr = paramsCsv(
      [{ endpointId: '1', name: '@evil, x', location: 'query', method: 'GET', pathTemplate: '/a' }],
      ['a', 'b', 'c', 'd', 'e', 'f']
    )
    expect(lines(pr)[1].startsWith(`"'@evil, x"`)).toBe(true)
  })

  it('guards header cells', () => {
    expect(lines(endpointsCsv([], ['=a', 'b', 'c', 'd', 'e', 'f', 'g']))[0].startsWith("'=a")).toBe(
      true
    )
  })
})
