import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'

vi.mock('@/context/search-provider', () => ({ useSearch: () => ({ setOpen: vi.fn() }) }))

const { Search } = await import('../search')
const { SkipToMain } = await import('../skip-to-main')

describe('header controls', () => {
  it('gives the search button an accessible name even when only its icon shows', () => {
    render(<Search />)
    expect(screen.getByRole('button', { name: 'Search' })).toBeInTheDocument()
  })

  it('speaks the reader language', () => {
    render(
      <I18nProvider locale="vi">
        <Search />
        <SkipToMain />
      </I18nProvider>
    )
    expect(screen.getByRole('button', { name: 'Tìm kiếm' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Chuyển tới nội dung chính' })).toBeInTheDocument()
  })
})
