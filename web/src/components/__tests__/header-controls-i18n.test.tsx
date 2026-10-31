import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'

vi.mock('@/context/search-provider', () => ({ useSearch: () => ({ setOpen: vi.fn() }) }))

const { Search } = await import('../search')
const { SkipToMain } = await import('../skip-to-main')

describe('header controls', () => {
  it('gives the search button an accessible name even when only its icon shows', () => {
    render(<Search />)
    expect(screen.getByRole('button', { name: 'Search or go to' })).toBeInTheDocument()
  })

  it('keeps the shortcut hint out of the name and states the shortcut instead', () => {
    // The visible label must be inside the accessible name (WCAG 2.5.3): the
    // kbd hint is hidden from it, the shortcut is announced as a shortcut.
    render(<Search />)
    const button = screen.getByRole('button', { name: 'Search or go to' })
    expect(button.getAttribute('aria-keyshortcuts')).toMatch(/^(Control|Meta)\+K$/)
    expect(button.querySelector('kbd')?.getAttribute('aria-hidden')).toBe('true')
  })

  it('speaks the reader language', () => {
    render(
      <I18nProvider locale="vi">
        <Search />
        <SkipToMain />
      </I18nProvider>
    )
    expect(screen.getByRole('button', { name: 'Tìm kiếm hoặc đi tới' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Chuyển tới nội dung chính' })).toBeInTheDocument()
  })
})
