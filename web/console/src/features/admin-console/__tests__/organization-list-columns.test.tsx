import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const keys: string[] = []
vi.mock('swr', () => ({
  default: (key: string) => {
    keys.push(key)
    return { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }
  },
}))

import { useOrganizations } from '../api/use-admin-organizations'
import { OrganizationStatePill } from '../components/organization-state-pill'

function Probe(props: Parameters<typeof useOrganizations>[0]) {
  useOrganizations(props)
  return null
}

describe('organization list: status and last member sign-in', () => {
  it('asks the API for one status only when the filter is set', () => {
    keys.length = 0
    render(<Probe status="suspended" />)
    render(<Probe />)
    expect(keys[0]).toContain('status=suspended')
    expect(keys[1]).not.toContain('status=')
  })

  it('names every status in words, never by colour alone', () => {
    const { rerender } = render(<OrganizationStatePill status="active" />)
    expect(screen.getByText('Active')).toBeInTheDocument()
    rerender(<OrganizationStatePill status="suspended" />)
    expect(screen.getByText('Suspended')).toBeInTheDocument()
    rerender(<OrganizationStatePill status="pending_deletion" />)
    expect(screen.getByText('Deletion scheduled')).toBeInTheDocument()
  })
})
