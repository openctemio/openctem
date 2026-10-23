import { describe, expect, it } from 'vitest'
import { assigneeLabel } from '../assignee-label'
import { toFindingDetail } from '../finding-detail'
import type { ApiFinding } from '../../api/finding-api.types'

const labels = { assigned: 'Assigned', unassigned: 'Unassigned' }

describe('assigneeLabel', () => {
  it('reads Unassigned only when there is no assignee', () => {
    expect(assigneeLabel(undefined, labels)).toBe('Unassigned')
    expect(assigneeLabel(null, labels)).toBe('Unassigned')
  })
  it('reads Assigned for an assignee whose name has not loaded', () => {
    expect(assigneeLabel({ name: '' }, labels)).toBe('Assigned')
    expect(assigneeLabel({ name: '  ' }, labels)).toBe('Assigned')
  })
  it('shows the name when known', () => {
    expect(assigneeLabel({ name: 'Admin User' }, labels)).toBe('Admin User')
  })
})

describe('toFindingDetail assignee', () => {
  const base = {
    id: 'f1',
    tenant_id: 't',
    asset_id: 'a',
    source: 'sca',
    tool_name: 'x',
    message: 'm',
    severity: 'high',
    status: 'new',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  } as unknown as ApiFinding

  it('never uses the raw id as the assignee name', () => {
    const d = toFindingDetail({ ...base, assigned_to: '11111111-2222-3333-4444-555555555555' })
    expect(d.assignee?.id).toBe('11111111-2222-3333-4444-555555555555')
    expect(d.assignee?.name).toBe('')
  })
  it('takes the enriched name', () => {
    const d = toFindingDetail({
      ...base,
      assigned_to: 'u1',
      assigned_to_user: { id: 'u1', name: 'Admin User', email: 'a@x.test' },
    })
    expect(d.assignee?.name).toBe('Admin User')
  })
})
