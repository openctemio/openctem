import axe from 'axe-core'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

const push = vi.fn()
let search = new URLSearchParams()
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push }),
  useSearchParams: () => search,
}))
const get = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => get(...a) }))

import { FindingListCrumb } from '../finding-list-crumb'
import { writeListContext } from '../../../lib/list-context'

const id = (n: number) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`

beforeEach(() => {
  push.mockReset()
  get.mockReset()
  search = new URLSearchParams()
  window.sessionStorage.clear()
  writeListContext({
    query: 'priority_class=P0,P1',
    label: 'Open P0 and P1',
    returnPath: '/findings?priority_class=P0,P1',
    ids: [id(1), id(2), id(3)],
    offset: 0,
    perPage: 3,
    total: 5,
  })
})

describe('FindingListCrumb', () => {
  it('shows the list, the position and prev/next links', async () => {
    get.mockResolvedValue({ data: [{ id: id(4) }, { id: id(5) }], total: 5 })
    const { container } = render(<FindingListCrumb findingId={id(2)} />)
    const back = await screen.findByRole('link', { name: 'Open P0 and P1' })
    expect(back.getAttribute('href')).toBe('/findings?priority_class=P0,P1')
    expect(screen.getByText('2 of 5')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Previous finding (k)' }).getAttribute('href')).toBe(
      `/findings/${id(1)}`
    )
    expect(screen.getByRole('link', { name: 'Next finding (j)' }).getAttribute('href')).toBe(
      `/findings/${id(3)}`
    )
    const res = await axe.run(container, { rules: { region: { enabled: false } } })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })

  it('j and k move through the list, not while typing', async () => {
    render(
      <>
        <input aria-label="note" />
        <FindingListCrumb findingId={id(2)} />
      </>
    )
    await screen.findByText('2 of 5')
    fireEvent.keyDown(screen.getByLabelText('note'), { key: 'j' })
    expect(push).not.toHaveBeenCalled()
    fireEvent.keyDown(document.body, { key: 'j' })
    expect(push).toHaveBeenCalledWith(`/findings/${id(3)}`)
    fireEvent.keyDown(document.body, { key: 'k' })
    expect(push).toHaveBeenLastCalledWith(`/findings/${id(1)}`)
  })

  it('reads the next page through the list API at the edge', async () => {
    get.mockResolvedValue({ data: [{ id: id(4) }, { id: id(5) }], total: 5 })
    render(<FindingListCrumb findingId={id(3)} />)
    await waitFor(() =>
      expect(screen.getByRole('link', { name: 'Next finding (j)' }).getAttribute('href')).toBe(
        `/findings/${id(4)}`
      )
    )
    expect(get).toHaveBeenCalledWith('/api/v1/findings?priority_class=P0%2CP1&page=2&per_page=3')
  })

  it('renders nothing for a finding not opened from the list, or opened from a task', async () => {
    const { container, rerender } = render(<FindingListCrumb findingId={id(9)} />)
    await new Promise((r) => setTimeout(r, 0))
    expect(container.innerHTML).toBe('')
    search = new URLSearchParams('from=task:abc')
    rerender(<FindingListCrumb findingId={id(2)} />)
    await new Promise((r) => setTimeout(r, 0))
    expect(container.innerHTML).toBe('')
  })
})
