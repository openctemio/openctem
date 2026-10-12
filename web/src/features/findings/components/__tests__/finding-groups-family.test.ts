import { describe, expect, it } from 'vitest'

import { buildFindingsEndpoint } from '../../api/use-findings-api'
import { groupRowFilter } from '../finding-groups-table'

describe('family group rows', () => {
  it('open the list filtered by the family', () => {
    const url = buildFindingsEndpoint({ ...groupRowFilter('family', 'CGI abuses') })
    expect(new URLSearchParams(url.split('?')[1]).get('family')).toBe('CGI abuses')
  })
})
