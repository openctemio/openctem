import { describe, it, expect } from 'vitest'

import { ApiClientError } from '@/lib/api/error-handler'
import { becomesInternal, transferBlocker, transferErrorKey } from '../ownership-transfer'
import type { MemberWithUser } from '../../types/member.types'

const base: MemberWithUser = {
  id: 'm1',
  user_id: 'u1',
  role: 'member',
  joined_at: '2026-01-01T00:00:00Z',
  email: 'pat@example.com',
  name: 'Pat',
  status: 'active',
  mfa_status: 'enabled',
  kind: 'internal',
}

describe('transferBlocker', () => {
  it('lets an active internal member with two-factor qualify', () => {
    expect(transferBlocker(base)).toBeNull()
  })
  it('refuses the owner, an inactive member, a managed outsider and no two-factor', () => {
    expect(transferBlocker({ ...base, role: 'owner' })?.key).toBe('org.ownership.blocker.owner')
    expect(transferBlocker({ ...base, status: 'suspended' })?.key).toBe(
      'org.ownership.blocker.inactive'
    )
    expect(
      transferBlocker({ ...base, kind: 'external', home_organization: 'Other Org' })?.key
    ).toBe('org.ownership.blocker.managed')
    expect(transferBlocker({ ...base, mfa_status: 'disabled' })?.key).toBe(
      'org.ownership.blocker.mfa'
    )
    expect(transferBlocker({ ...base, mfa_status: 'idp' })?.key).toBe('org.ownership.blocker.mfa')
  })
  it('lets an unmanaged outsider qualify, who becomes internal', () => {
    const outsider = { ...base, kind: 'external' as const }
    expect(transferBlocker(outsider)).toBeNull()
    expect(becomesInternal(outsider)).toBe(true)
    expect(becomesInternal(base)).toBe(false)
  })
})

describe('transferErrorKey', () => {
  it('maps API codes to translated messages', () => {
    expect(transferErrorKey(new ApiClientError('x', 'OWNERSHIP_TARGET_NEEDS_MFA', 400))?.key).toBe(
      'org.ownership.blocker.mfa'
    )
    expect(transferErrorKey(new ApiClientError('x', 'OWNERSHIP_TRANSFER_PENDING', 409))?.key).toBe(
      'org.ownership.error.pending'
    )
    expect(transferErrorKey(new ApiClientError('x', 'OTHER', 400))).toBeNull()
    expect(transferErrorKey(new Error('x'))).toBeNull()
  })
})
