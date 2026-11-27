import { describe, expect, it } from 'vitest'
import { translate, type TranslateVars } from '@/lib/i18n'
import { vi as viDict } from '@/lib/i18n/dictionaries/vi'
import { describeFindingEvent, toFindingActivityItems } from '../finding-activity-items'
import type { Activity } from '../../types'

const tVi = (key: string, fallback?: string, vars?: TranslateVars) =>
  translate(viDict, key, fallback, vars, 'vi')

const at = '2026-05-10T10:00:00Z'
const jamie = { id: 'u1', name: 'Jamie', email: 'j@x.test', role: 'analyst' as const }

function act(activityType: string, extra: Partial<Activity> = {}): Activity {
  return {
    id: `a-${activityType}`,
    type: 'status_changed',
    actor: jamie,
    metadata: { activityType },
    createdAt: at,
    ...extra,
  } as Activity
}

// Every event the formatter words itself (the others show the API's content).
const EVENTS: Activity[] = [
  act('created'),
  act('scan_detected', { metadata: { activityType: 'scan_detected', scanName: 'nightly' } }),
  act('status_changed', { previousValue: 'confirmed', newValue: 'in_progress' }),
  act('auto_resolved'),
  act('auto_reopened'),
  act('reopened'),
  act('severity_changed', { previousValue: 'low', newValue: 'medium' }),
  act('assigned', { metadata: { activityType: 'assigned', assigneeName: 'Jamie' } }),
  act('unassigned'),
  act('sla_warning'),
  act('sla_breach'),
  act('linked', { metadata: { activityType: 'linked', ticket_key: 'OPS-1' } }),
  act('unlinked'),
  act('duplicate_marked'),
  act('issue_linked'),
  act('issue_unlinked'),
  act('false_positive_marked'),
  act('evidence_added'),
  act('verified'),
  act('ai_triage_requested'),
  act('ai_triage', { metadata: { activityType: 'ai_triage', severity: 'high' } }),
  act('ai_triage_failed'),
  act('comment_deleted'),
]

describe('finding activity in Vietnamese', () => {
  it('words every event from the catalog', () => {
    for (const a of EVENTS) {
      const en = describeFindingEvent(a)?.summary
      const vi = describeFindingEvent(a, tVi)?.summary
      expect(vi, String(a.metadata?.activityType)).toBeTruthy()
      expect(vi, String(a.metadata?.activityType)).not.toBe(en)
      expect(vi, String(a.metadata?.activityType)).not.toMatch(/findings\.activity\./)
    }
  })

  it('keeps names and translates the status and severity words', () => {
    const status = describeFindingEvent(EVENTS[2], tVi)?.summary
    expect(status).toBe(
      `đã đổi trạng thái ${tVi('findings.status.confirmed')} → ${tVi('findings.status.in_progress')}`
    )
    expect(describeFindingEvent(EVENTS[6], tVi)?.summary).toBe('đã đổi mức độ Thấp → Trung bình')
    expect(describeFindingEvent(EVENTS[1], tVi)?.summary).toContain('(nightly)')
  })

  it('a scanner that recorded the finding is the actor, the verb is translated', () => {
    const items = toFindingActivityItems(
      [{ id: 'c', type: 'created', actor: 'system', content: 'Recorded by nuclei', createdAt: at }],
      undefined,
      { t: tVi }
    )
    expect(items[0]).toMatchObject({
      kind: 'event',
      actor: { name: 'nuclei' },
      summary: 'đã ghi nhận phát hiện này',
    })
  })

  it('stays English without a translator', () => {
    expect(describeFindingEvent(act('created'))?.summary).toBe('recorded this finding')
  })
})
