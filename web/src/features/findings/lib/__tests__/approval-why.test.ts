import { describe, expect, it } from 'vitest'
import { approvalWaitReasons, needsApprovalLevel } from '../approval-why'

const t = (_k: string, fallback?: string) => fallback ?? _k

const fp = { requested_status: 'false_positive' }

describe('approvalWaitReasons', () => {
  it('says the organization asks a second person for every false positive', () => {
    expect(
      approvalWaitReasons(
        t,
        { ...fp, policy_reasons: ['fp_level'] },
        { isRequester: true, level: 'all' }
      )
    ).toEqual(['Your organization asks a second person to check every false positive.'])
  })

  it('says "every serious" under the serious-only level', () => {
    expect(
      approvalWaitReasons(
        t,
        { ...fp, policy_reasons: ['fp_level'] },
        { isRequester: true, level: 'high_and_above' }
      )
    ).toEqual(['Your organization asks a second person to check every serious false positive.'])
  })

  it('words accepted risks with their own level', () => {
    expect(
      approvalWaitReasons(
        t,
        { requested_status: 'accepted', policy_reasons: ['accept_level'] },
        { isRequester: false, level: 'all' }
      )
    ).toEqual(['Your organization asks a second person to check every accepted risk.'])
  })

  it('names asset ownership for the requester and for others', () => {
    const a = { ...fp, policy_reasons: ['requester_owns_asset'] }
    expect(approvalWaitReasons(t, a, { isRequester: true })).toEqual([
      'You own this asset, so someone else must check it.',
    ])
    expect(approvalWaitReasons(t, a, { isRequester: false })[0]).toMatch(/person who asked owns/)
  })

  it('says automation and AI always need a person', () => {
    expect(
      approvalWaitReasons(
        t,
        { ...fp, policy_reasons: ['automation_cannot_decide', 'requester_cannot_decide_alone'] },
        { isRequester: false }
      )
    ).toEqual(['Requests made by automation or AI always need a person.'])
  })

  it('says nobody else can approve, unless the sole owner may approve it themselves', () => {
    const a = { ...fp, policy_reasons: ['no_eligible_approver'], eligible_approver_count: 0 }
    expect(approvalWaitReasons(t, a, { isRequester: true })).toEqual([
      'Nobody else can approve this. Ask an owner to give someone the approve permission.',
    ])
    expect(
      approvalWaitReasons(t, { ...a, self_approval_available: true }, { isRequester: true })
    ).toEqual([])
    // An older request without the count says nothing it cannot know.
    expect(
      approvalWaitReasons(t, { ...a, eligible_approver_count: null }, { isRequester: true })
    ).toEqual([])
  })

  it('is empty without stored reasons', () => {
    expect(approvalWaitReasons(t, fp, { isRequester: true })).toEqual([])
  })

  it('reads the level only when the level is a reason', () => {
    expect(needsApprovalLevel({ policy_reasons: ['fp_level'] })).toBe(true)
    expect(needsApprovalLevel({ policy_reasons: ['requester_owns_asset'] })).toBe(false)
    expect(needsApprovalLevel({})).toBe(false)
  })
})
