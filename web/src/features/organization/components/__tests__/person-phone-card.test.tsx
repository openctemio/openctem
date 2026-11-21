/**
 * The members and invitations phone card: the address is shown once (never
 * as title and subtitle), a long address breaks inside the card, and the
 * menu has a column of its own so it never covers text. Layout is measured
 * at 390 px on a build; this pins the rules the card applies.
 */
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { PersonPhoneCard, distinctAddress } from '../person-phone-card'

describe('distinctAddress', () => {
  it('shows the address under a real name only', () => {
    expect(distinctAddress('Example Person', 'person@example.com')).toBe('person@example.com')
    expect(distinctAddress('', 'person@example.com')).toBeUndefined()
    expect(distinctAddress(undefined, 'person@example.com')).toBeUndefined()
    // An account whose name is its address: once, not twice.
    expect(distinctAddress(' Person@Example.com ', 'person@example.com')).toBeUndefined()
  })
})

describe('PersonPhoneCard', () => {
  const long = 'nguyen.thi.minh.chau.phong.an.toan.thong.tin@tong-cong-ty-buu-chinh.example.com'

  it('breaks a long address inside the card and keeps the menu in its own column', () => {
    render(
      <PersonPhoneCard
        title={long}
        facts={<span>Member</span>}
        menu={<button aria-label="Actions">...</button>}
      />
    )
    const title = screen.getByText(long)
    expect(title.className).toContain('[overflow-wrap:anywhere]')
    expect(title.closest('.flex-1')?.className).toContain('min-w-0')
    const menuBox = screen.getByRole('button', { name: 'Actions' }).parentElement as HTMLElement
    expect(menuBox.className).toContain('shrink-0')
    // The menu is a sibling of the text column, not inside the title line.
    expect(menuBox.contains(title)).toBe(false)
    expect(title.parentElement?.contains(menuBox)).toBe(false)
    expect(document.querySelector('[data-slot=person-card-address]')).toBeNull()
  })

  it('shows name, address and facts once each, and opens on a tap outside its buttons', () => {
    const onOpen = vi.fn()
    render(
      <PersonPhoneCard
        title="Example Person"
        address="person@example.com"
        facts={
          <>
            <span>Administrator</span>
            <span>Active</span>
          </>
        }
        menu={<button aria-label="Actions">...</button>}
        onOpen={onOpen}
      />
    )
    expect(screen.getAllByText('person@example.com')).toHaveLength(1)
    expect(document.querySelector('[data-slot=person-card-facts]')?.className).toContain(
      'flex-wrap'
    )
    fireEvent.click(screen.getByText('Active'))
    expect(onOpen).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(onOpen).toHaveBeenCalledTimes(1)
  })

  it('ends in a chevron when it opens on a tap but has no menu', () => {
    const { rerender } = render(<PersonPhoneCard title="Viewer" onOpen={vi.fn()} />)
    expect(document.querySelector('[data-slot=person-card-chevron]')).not.toBeNull()
    rerender(<PersonPhoneCard title="Viewer" onOpen={vi.fn()} menu={<button>m</button>} />)
    expect(document.querySelector('[data-slot=person-card-chevron]')).toBeNull()
    rerender(<PersonPhoneCard title="Viewer" />)
    expect(document.querySelector('[data-slot=person-card-chevron]')).toBeNull()
  })
})
