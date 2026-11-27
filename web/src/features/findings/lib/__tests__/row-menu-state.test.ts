import { describe, expect, it } from 'vitest'

import { ALL_FINDING_STATUSES, FINDING_STATUS_CONFIG } from '../../types'
import { HUMAN_SOURCES } from '../finding-detail'
import { ROW_MENU_REASON_FALLBACK, rowMenuBlocks } from '../row-menu-state'

describe('rowMenuBlocks', () => {
  it('blocks nothing on an open scanner finding without a ticket', () => {
    expect(rowMenuBlocks({ status: 'new', source: 'sast' })).toEqual({})
    expect(rowMenuBlocks({ status: 'confirmed', source: 'dast', workItemUris: [] })).toEqual({})
  })

  it('blocks a second ticket once one is linked', () => {
    expect(
      rowMenuBlocks({
        status: 'new',
        source: 'sast',
        workItemUris: ['https://tickets.example.com/SEC-1'],
      })
    ).toEqual({ create_ticket: 'ticketLinked' })
  })

  it('blocks false positive on every closed status and on no other', () => {
    for (const status of ALL_FINDING_STATUSES) {
      const block = rowMenuBlocks({ status, source: 'sast' }).false_positive
      if (status === 'false_positive') expect(block).toBe('alreadyFalsePositive')
      else if (FINDING_STATUS_CONFIG[status].category === 'closed') expect(block).toBe('closed')
      else expect(block).toBeUndefined()
    }
  })

  it('leaves the status item on a closed finding: it can be reopened', () => {
    expect(rowMenuBlocks({ status: 'resolved', source: 'sast' }).status).toBeUndefined()
  })

  it('blocks assign, status and false positive for the sources the drawer locks', () => {
    for (const source of HUMAN_SOURCES) {
      expect(rowMenuBlocks({ status: 'confirmed', source: source as never })).toEqual({
        assign: 'managedElsewhere',
        status: 'managedElsewhere',
        false_positive: 'managedElsewhere',
      })
    }
  })

  it('has a sentence for every reason code', () => {
    for (const text of Object.values(ROW_MENU_REASON_FALLBACK)) expect(text).toMatch(/\.$/)
  })
})
