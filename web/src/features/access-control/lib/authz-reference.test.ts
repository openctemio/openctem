import { describe, expect, it } from 'vitest'
import {
  featureCapabilities,
  isAdminBypassRole,
  passesGate,
  roleTemplates,
  type AuthzReference,
} from './authz-reference'

const ref: AuthzReference = {
  version: 1,
  permissions: [
    { id: 'findings:read', module: 'findings', name: 'View findings' },
    { id: 'findings:verify', module: 'findings', name: 'Verify fixes' },
    { id: 'findings:fix_apply', module: 'findings', name: 'Mark fix applied' },
  ],
  roles: [
    {
      id: 'owner',
      kind: 'system',
      name: 'Owner',
      description: '',
      has_full_data_access: true,
      admin_bypass: true,
      permissions: [],
    },
    {
      id: 'remediation-owner',
      kind: 'template',
      name: 'Remediation owner',
      description: '',
      has_full_data_access: false,
      permissions: ['findings:read', 'findings:fix_apply'],
    },
  ],
  features: [
    {
      id: 'findings',
      title: 'Findings',
      description: '',
      permissions: ['findings:fix_apply', 'findings:read', 'findings:verify'],
      routes: [
        {
          method: 'GET',
          path: '/api/v1/findings',
          gate: { permissions: ['findings:read'] },
          data_scope: { class: 'scoped' },
        },
        {
          method: 'POST',
          path: '/api/v1/findings/{id}/verify',
          gate: { permissions: ['findings:verify'] },
          data_scope: { class: 'scoped' },
        },
        {
          method: 'POST',
          path: '/api/v1/findings/actions/fix-applied',
          gate: { permissions: ['findings:fix_apply'] },
          data_scope: { class: 'scoped' },
        },
        {
          method: 'DELETE',
          path: '/api/v1/findings/{id}',
          gate: { permissions: ['findings:read'], min_role: 'admin' },
          data_scope: { class: 'scoped' },
        },
        {
          method: 'GET',
          path: '/api/v1/me',
          gate: {},
          data_scope: { class: 'system' },
          ungated: 'self',
        },
      ],
    },
    { id: 'system', title: 'System', description: '', permissions: [], routes: [] },
  ],
}

describe('authz reference', () => {
  it('passesGate follows permissions, any-of and the admin bypass', () => {
    expect(passesGate({ permissions: ['a'] }, ['a'], false)).toBe(true)
    expect(passesGate({ permissions: ['a', 'b'] }, ['a'], false)).toBe(false)
    expect(passesGate({ any_of: [['a', 'b']] }, ['b'], false)).toBe(true)
    expect(passesGate({ any_of: [['a', 'b']] }, ['c'], false)).toBe(false)
    expect(passesGate({ permissions: ['x'] }, [], true)).toBe(true)
  })

  it('a team-role gate passes only the owner and admin', () => {
    expect(passesGate({ min_role: 'admin' }, ['anything'], false)).toBe(false)
    expect(passesGate({ min_role: 'admin' }, [], true)).toBe(true)
  })

  it('featureCapabilities counts the gated actions a role passes', () => {
    const [findings] = featureCapabilities(ref, ['findings:read', 'findings:fix_apply'], false)
    expect(findings.feature.id).toBe('findings')
    expect(findings.gatedRoutes).toBe(4)
    expect(findings.allowedRoutes).toBe(2) // read and fix applied; not verify, not the admin route
    expect(findings.held).toEqual(['findings:fix_apply', 'findings:read'])
  })

  it('an admin-bypass role passes everything', () => {
    const [findings] = featureCapabilities(ref, [], true)
    expect(findings.allowedRoutes).toBe(findings.gatedRoutes)
    expect(findings.held).toEqual(findings.feature.permissions)
  })

  it('features without permissions are left out', () => {
    expect(featureCapabilities(ref, [], false).map((c) => c.feature.id)).toEqual(['findings'])
  })

  it('roleTemplates returns templates only', () => {
    expect(roleTemplates(ref).map((r) => r.id)).toEqual(['remediation-owner'])
  })

  it('only system owner and admin bypass', () => {
    expect(isAdminBypassRole('owner', true)).toBe(true)
    expect(isAdminBypassRole('admin', true)).toBe(true)
    expect(isAdminBypassRole('admin', false)).toBe(false)
    expect(isAdminBypassRole('member', true)).toBe(false)
  })
})
