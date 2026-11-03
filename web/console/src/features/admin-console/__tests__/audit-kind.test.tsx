import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const keys: string[] = []
vi.mock('swr', () => ({
  default: (key: string) => {
    keys.push(key)
    return { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }
  },
}))

import { useAdminAuditLogs } from '../api/use-admin-audit'
import { AuditKindLens, auditKind } from '../components/audit-kind-lens'

function Probe(props: Parameters<typeof useAdminAuditLogs>[0]) {
  useAdminAuditLogs(props)
  return null
}

describe('administrator audit: changes or all events', () => {
  it('asks the API for changes only when the list shows changes', () => {
    keys.length = 0
    render(<Probe page={1} kind="changes" />)
    render(<Probe page={1} kind="all" />)
    render(<Probe page={1} />)
    expect(keys[0]).toContain('kind=changes')
    expect(keys[1]).not.toContain('kind=')
    expect(keys[2]).not.toContain('kind=')
  })

  it('reads an empty or unknown filter as changes, the default', () => {
    expect(auditKind('')).toBe('changes')
    expect(auditKind(undefined)).toBe('changes')
    expect(auditKind('views')).toBe('changes')
    expect(auditKind('all')).toBe('all')
  })

  it('switches between Changes and All events with the shared filter token', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<AuditKindLens value="changes" onChange={onChange} />)
    await user.click(screen.getByRole('button', { name: 'Which events: Changes' }))
    await user.click(await screen.findByRole('menuitemradio', { name: /All events/ }))
    expect(onChange).toHaveBeenCalledWith('all')
  })
})
