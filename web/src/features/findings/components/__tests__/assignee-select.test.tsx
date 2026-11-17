import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AssigneeSelect } from '../assignee-select'

const assignable = vi.fn()
const members = vi.fn()
vi.mock('../../api/use-assignable-members', () => ({
  useAssignableMembers: (...args: unknown[]) => assignable(...args),
}))
vi.mock('@/features/organization/api/use-members', () => ({
  useMembers: (...args: unknown[]) => members(...args),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-1' } }),
}))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback?: string, vars?: Record<string, unknown>) =>
      (fallback ?? _k).replace(/\{(\w+)\}/g, (_m, k) => String(vars?.[k] ?? '')),
  }),
}))

// The hook the kit's ResponsivePopover reads: phone-sized below 768 px.
const mobile = vi.hoisted(() => ({ value: false }))
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => mobile.value }))

/** A phone: a coarse pointer that cannot hover. */
function emulateTouch() {
  vi.stubGlobal(
    'matchMedia',
    (query: string) =>
      ({
        matches: query.includes('pointer: coarse'),
        media: query,
        addEventListener() {},
        removeEventListener() {},
      }) as unknown as MediaQueryList
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

beforeEach(() => {
  mobile.value = false
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  )
  Element.prototype.scrollIntoView = vi.fn()
  assignable.mockReset()
  members.mockReset()
  members.mockReturnValue({
    members: [{ user_id: 'u-all', name: 'Every Member', email: 'e@x.test' }],
    total: 1,
    isLoading: false,
  })
  assignable.mockReturnValue({
    members: [{ user_id: 'u-ok', name: 'Readable Person', role: 'member' }],
    isLoading: false,
  })
})

describe('AssigneeSelect', () => {
  it('lists only the members the server says can read the finding', async () => {
    render(<AssigneeSelect findingId="f-1" onChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('button'))
    expect(screen.getByText('Readable Person')).toBeInTheDocument()
    expect(screen.queryByText('Every Member')).not.toBeInTheDocument()
    // The plain member list is not requested for a single finding.
    expect(members.mock.calls.every(([tenant]) => tenant === undefined)).toBe(true)
    expect(assignable).toHaveBeenLastCalledWith('f-1', expect.objectContaining({ enabled: true }))
  })

  it('without a finding (bulk) keeps the member list and does not ask the finding endpoint', async () => {
    assignable.mockReturnValue({ members: [], isLoading: false })
    render(<AssigneeSelect onChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('button'))
    expect(screen.getByText('Every Member')).toBeInTheDocument()
    expect(assignable).toHaveBeenLastCalledWith(undefined, expect.anything())
  })

  it('passes the chosen member to onChange', async () => {
    const onChange = vi.fn()
    render(<AssigneeSelect findingId="f-1" onChange={onChange} />)
    await userEvent.click(screen.getByRole('button'))
    await userEvent.click(screen.getByText('Readable Person'))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'u-ok', name: 'Readable Person' })
    )
  })

  it('from 768 px up is the anchored popover with its width, the search field focused', async () => {
    render(<AssigneeSelect findingId="f-1" onChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('button'))
    const popover = await screen.findByRole('dialog', { name: 'Select a person' })
    expect(popover.closest('[data-slot="responsive-popover-sheet"]')).toBeNull()
    expect(popover).toHaveClass('w-56', 'p-0')
    await waitFor(() => expect(screen.getByPlaceholderText('Search members...')).toHaveFocus())
  })

  it('below 768 px opens as a bottom sheet named by its title, the search field pinned on top', async () => {
    mobile.value = true
    render(<AssigneeSelect onChange={vi.fn()} title="Assign to" />)
    await userEvent.click(screen.getByRole('button'))
    const sheet = await screen.findByRole('dialog', { name: 'Assign to' })
    expect(sheet).toHaveAttribute('data-slot', 'responsive-popover-sheet')
    expect(sheet).not.toHaveClass('w-56')
    const body = screen.getByTestId('responsive-popover-body')
    expect(body).toContainElement(screen.getByPlaceholderText('Search members...'))
    expect(body).toContainElement(screen.getByText('Every Member'))
  })

  it('on a touch phone opens without the keyboard: the member list has focus, not the search field', async () => {
    mobile.value = true
    emulateTouch()
    render(<AssigneeSelect findingId="f-1" onChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('button'))
    await screen.findByRole('dialog', { name: 'Select a person' })
    const list = screen.getByRole('listbox')
    await waitFor(() => expect(list).toHaveFocus())
    expect(screen.getByPlaceholderText('Search members...')).not.toHaveFocus()
  })

  it('picking a member in the sheet reports it and closes the sheet', async () => {
    mobile.value = true
    const onChange = vi.fn()
    render(<AssigneeSelect findingId="f-1" onChange={onChange} />)
    await userEvent.click(screen.getByRole('button'))
    await screen.findByRole('dialog', { name: 'Select a person' })
    await userEvent.click(screen.getByText('Readable Person'))
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ id: 'u-ok' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })
})
