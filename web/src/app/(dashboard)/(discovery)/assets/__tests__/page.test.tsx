import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { TooltipProvider } from '@/components/ui/tooltip'
import AssetsPage from '../page'

let view = 'list'
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: () => [
    view,
    (next: string) => {
      view = next
    },
  ],
}))
vi.mock('@/features/assets/components/inventory/all-assets-inventory', () => ({
  AllAssetsInventory: ({ viewSwitcher }: { viewSwitcher?: React.ReactNode }) => (
    <div data-testid="list-view">{viewSwitcher}</div>
  ),
}))
vi.mock('@/features/assets/components/overview/asset-categories-view', () => ({
  AssetCategoriesView: ({ viewSwitcher }: { viewSwitcher?: React.ReactNode }) => (
    <div data-testid="categories-view">{viewSwitcher}</div>
  ),
}))

const renderPage = () =>
  render(
    <TooltipProvider>
      <AssetsPage />
    </TooltipProvider>
  )

describe('assets page view switcher', () => {
  beforeEach(() => {
    view = 'list'
  })

  it('hands the same translated switcher to the list view', () => {
    renderPage()
    expect(screen.getByTestId('list-view')).toContainElement(
      screen.getByRole('button', { name: 'List view' })
    )
    expect(screen.getByRole('button', { name: 'List view' })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
  })

  it('hands it to the category view too, with that view pressed, and switches', () => {
    view = 'categories'
    renderPage()
    expect(screen.getByTestId('categories-view')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Category view' })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
    fireEvent.click(screen.getByRole('button', { name: 'List view' }))
    expect(view).toBe('list')
  })
})
