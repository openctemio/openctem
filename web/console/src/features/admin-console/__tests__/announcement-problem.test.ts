import { describe, it, expect } from 'vitest'

import { announcementProblem } from '../components/publish-announcement-dialog'

describe('announcementProblem', () => {
  const now = new Date('2026-10-08T10:00:00Z')
  it('mirrors the API rules', () => {
    expect(announcementProblem('', now, new Date('2026-10-08T12:00:00Z'))).toMatch(/write/i)
    expect(announcementProblem('x'.repeat(501), now, new Date('2026-10-08T12:00:00Z'))).toMatch(
      /500/
    )
    expect(announcementProblem('ok', now, new Date('2026-10-08T09:00:00Z'))).toMatch(/after/)
    expect(announcementProblem('ok', now, new Date('2026-11-20T10:00:00Z'))).toMatch(/31 days/)
    expect(
      announcementProblem('Maintenance tonight', now, new Date('2026-10-08T12:00:00Z'))
    ).toBeNull()
  })
})
