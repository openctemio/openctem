import { describe, it, expect } from 'vitest'
import {
  DEFAULT_CELL,
  approveErrorOutcome,
  approveResultOutcome,
  cellChoices,
  tiersAtOrAbove,
  tiersForSave,
} from '../approval-policy'

// Echo the English fallback with its parameters filled in.
const t = ((_key: string, fallback?: string, params?: Record<string, unknown>) =>
  (fallback ?? '').replace(/\{(\w+)\}/g, (_m, k: string) => String(params?.[k] ?? ''))) as never

describe('tier choices', () => {
  it('never goes below the floor', () => {
    expect(tiersAtOrAbove('security')).toEqual(['security', 'dual'])
    expect(tiersAtOrAbove('peer')).toEqual(['peer', 'security', 'dual'])
    expect(tiersAtOrAbove(undefined)).toEqual(['single', 'peer', 'security', 'dual'])
  })

  it('offers only raises for a false positive', () => {
    expect(cellChoices('false_positive', 'single')).toEqual(['peer', 'security', 'dual'])
    expect(cellChoices('accepted', 'security')).toEqual(['security', 'dual'])
  })
})

describe('tiersForSave', () => {
  const floors = { 'accepted.critical': 'security', 'false_positive.high': 'single' }
  const defaults = { 'accepted.critical': 'dual', 'false_positive.high': 'peer' }

  it('drops default cells, cells equal to the default and tiers below the floor', () => {
    expect(
      tiersForSave(
        {
          'accepted.critical': 'dual', // = default
          'false_positive.high': DEFAULT_CELL,
        },
        floors,
        defaults
      )
    ).toEqual({})
    expect(tiersForSave({ 'accepted.critical': 'peer' }, floors, defaults)).toEqual({})
  })

  it('keeps a stricter or a between-floor-and-default choice, and any false-positive raise', () => {
    expect(
      tiersForSave(
        { 'accepted.critical': 'security', 'false_positive.high': 'peer' },
        floors,
        defaults
      )
    ).toEqual({ 'accepted.critical': 'security', 'false_positive.high': 'peer' })
  })
})

describe('approve outcomes', () => {
  it('reads a pending sign-off as recorded with the remaining count', () => {
    expect(
      approveResultOutcome({ status: 'pending', approvals_required: 2, approvals_collected: 1 })
    ).toEqual({ kind: 'recorded', remaining: 1 })
    expect(approveResultOutcome({ status: 'approved' })).toEqual({ kind: 'applied' })
  })

  it('localizes the refusal reasons', () => {
    expect(
      approveErrorOutcome(t, {
        statusCode: 403,
        code: 'APPROVER_NOT_ELIGIBLE',
        details: { reason: 'asset_owner' },
      })
    ).toEqual({
      kind: 'refused',
      message: "You own this finding's asset, so you cannot approve hiding its risk.",
    })
    expect(
      approveErrorOutcome(t, {
        code: 'APPROVER_NOT_ELIGIBLE',
        details: { reason: 'not_in_security_pool' },
      })
    ).toMatchObject({ message: 'This request needs an approver from the security pool.' })
    expect(approveErrorOutcome(t, { code: 'NO_ELIGIBLE_APPROVER', statusCode: 409 })).toMatchObject(
      { kind: 'refused' }
    )
    expect(approveErrorOutcome(t, { code: 'STEP_UP_REQUIRED', statusCode: 403 })).toMatchObject({
      kind: 'refused',
      message: 'Confirm your identity to approve this request.',
    })
    expect(approveErrorOutcome(t, new Error('boom'))).toEqual({ kind: 'failed' })
  })
})
