import { describe, it, expect } from 'vitest'
import { PEER_ADMIN_LOCK_REASON, canResetMemberMfa, isPeerAdminLocked } from '../lib/member-policy'

const admin = { role: 'admin', user_id: 'u-admin' }
const member = { role: 'member', user_id: 'u-member' }
const viewer = { role: 'viewer', user_id: 'u-viewer' }

describe('isPeerAdminLocked', () => {
  it('locks another administrator for a caller who is not the owner', () => {
    expect(isPeerAdminLocked(admin, { isOwner: false, userId: 'u-other-admin' })).toBe(true)
  })

  it('does not lock administrators for the owner', () => {
    expect(isPeerAdminLocked(admin, { isOwner: true, userId: 'u-owner' })).toBe(false)
  })

  it('does not lock members and viewers', () => {
    expect(isPeerAdminLocked(member, { isOwner: false, userId: 'u-admin' })).toBe(false)
    expect(isPeerAdminLocked(viewer, { isOwner: false, userId: 'u-admin' })).toBe(false)
  })

  it('does not lock an administrator acting on themselves', () => {
    expect(isPeerAdminLocked(admin, { isOwner: false, userId: 'u-admin' })).toBe(false)
  })

  it('explains the rule', () => {
    expect(PEER_ADMIN_LOCK_REASON).toMatch(/only the organization owner/i)
  })
})

describe('canResetMemberMfa', () => {
  const on = (m: { role: string; user_id: string }) => ({ ...m, mfa_status: 'enabled' })
  const owner = { role: 'owner', user_id: 'u-owner' }
  const adminCaller = { isOwner: false, userId: 'u-admin2' }
  const ownerCaller = { isOwner: true, userId: 'u-owner2' }

  it('lets an administrator reset a member or viewer with 2FA on', () => {
    expect(canResetMemberMfa(on(member), adminCaller)).toBe(true)
    expect(canResetMemberMfa(on(viewer), adminCaller)).toBe(true)
  })

  it('needs 2FA to be on', () => {
    expect(canResetMemberMfa({ ...member, mfa_status: 'disabled' }, adminCaller)).toBe(false)
    expect(canResetMemberMfa({ ...member, mfa_status: 'idp' }, adminCaller)).toBe(false)
    expect(canResetMemberMfa(member, adminCaller)).toBe(false)
  })

  it('keeps owner and administrator targets for the owner', () => {
    expect(canResetMemberMfa(on(admin), adminCaller)).toBe(false)
    expect(canResetMemberMfa(on(owner), adminCaller)).toBe(false)
    expect(canResetMemberMfa(on(admin), ownerCaller)).toBe(true)
    expect(canResetMemberMfa(on(owner), ownerCaller)).toBe(true)
  })

  it('never offers a reset of the caller themself', () => {
    expect(canResetMemberMfa(on(owner), { isOwner: true, userId: 'u-owner' })).toBe(false)
    expect(canResetMemberMfa(on(member), { isOwner: false })).toBe(false)
  })
})
