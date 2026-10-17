import { describe, expect, it } from 'vitest'
import en from '@/lib/i18n/dictionaries/en/findings.json'
import vi from '@/lib/i18n/dictionaries/vi/findings.json'
import { summarizeDryRun, transitionReason } from '../transition-reasons'

const t = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  (fallback ?? key).replace(/\{(\w+)\}/g, (_, k: string) => String(vars?.[k] ?? ''))

describe('transition reasons', () => {
  it('every reason code has an English and a Vietnamese sentence', () => {
    for (const code of [
      'missing_permission',
      'not_a_lifecycle_move',
      'not_fix_owner',
      'not_a_person',
      'ticket_cannot_close',
      'pentest_module',
      'evidence_required',
      'checklist_required',
      'not_found',
      'not_in_lifecycle',
      'same_sub_status',
      'closure_reason_change',
      'platform_sub_status',
      'lifecycle_permission',
      'actor_kind_denied',
      'fields_required',
      'note_too_short',
    ]) {
      expect((en as Record<string, string>)[`findings.transitionReason.${code}`], code).toBeTruthy()
      expect((vi as Record<string, string>)[`findings.transitionReason.${code}`], code).toBeTruthy()
    }
  })

  it('names the permission a move needs', () => {
    expect(
      transitionReason(t, { code: 'missing_permission', params: { permission: 'findings:verify' } })
    ).toContain('findings:verify')
  })

  it('splits a dry run into the movable ids and counted reasons', () => {
    const out = summarizeDryRun(t, [
      { finding_id: 'a', decision: { to: 'resolved', allowed: true } },
      {
        finding_id: 'b',
        decision: { to: 'resolved', allowed: false, blocked: [{ code: 'not_fix_owner' }] },
      },
      {
        finding_id: 'c',
        decision: { to: 'resolved', allowed: false, blocked: [{ code: 'not_fix_owner' }] },
      },
      { finding_id: 'd', not_found: true },
    ])
    expect(out.allowed).toEqual(['a'])
    expect(out.refused).toHaveLength(2)
    expect(out.refused.find((r) => r.count === 2)).toBeTruthy()
  })

  it('refuses up front a bulk move the lifecycle asks fields or a longer note for', () => {
    const out = summarizeDryRun(
      t,
      [
        { finding_id: 'a', decision: { to: 'resolved', allowed: true } },
        {
          finding_id: 'b',
          decision: { to: 'resolved', allowed: true, fields: ['ticket_link', 'change_id'] },
        },
        { finding_id: 'c', decision: { to: 'resolved', allowed: true, note_min_len: 30 } },
        { finding_id: 'd', decision: { to: 'resolved', allowed: true, note_min_len: 5 } },
      ],
      { note: 'short note' }
    )
    expect(out.allowed).toEqual(['a', 'd'])
    expect(out.refused.map((r) => r.reason)).toEqual([
      'Needs ticket_link, change_id: change these findings one at a time',
      'Needs a note of at least 30 characters',
    ])
  })

  it("names the organization's required permissions", () => {
    expect(
      transitionReason(t, {
        code: 'lifecycle_permission',
        params: { any_of: 'findings:verify,findings:triage' },
      })
    ).toContain('findings:verify, findings:triage')
  })
})
