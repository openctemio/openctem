import { describe, it, expect } from 'vitest'

import { announcementProblem } from '../components/publish-announcement-dialog'

describe('announcementProblem', () => {
  const now = new Date('2026-10-08T10:00:00Z')
  it('mirrors the API rules', () => {
    expect(announcementProblem('', now, new Date('2026-10-08T12:00:00Z'))).toBe('empty')
    expect(announcementProblem('x'.repeat(501), now, new Date('2026-10-08T12:00:00Z'))).toBe(
      'tooLong'
    )
    expect(announcementProblem('ok', now, new Date('2026-10-08T09:00:00Z'))).toBe('endBeforeStart')
    expect(announcementProblem('ok', now, new Date('2026-11-20T10:00:00Z'))).toBe('tooManyDays')
    expect(
      announcementProblem('Maintenance tonight', now, new Date('2026-10-08T12:00:00Z'))
    ).toBeNull()
  })
})
