import { describe, expect, it } from 'vitest'
import en from '@/lib/i18n/dictionaries/en/findings.json'
import vi from '@/lib/i18n/dictionaries/vi/findings.json'
import { summarizeDryRun, transitionReason } from '../transition-reasons'

const t = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  (fallback ?? key).replace('{permission}', String(vars?.permission ?? ''))

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
})
