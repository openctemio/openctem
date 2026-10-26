/**
 * /findings/<not a uuid> shows the not-found block and never mounts the detail
 * page (which would call the API with a bad id); a UUID renders the page.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

let id = 'imports'
vi.mock('next/navigation', () => ({
  useParams: () => ({ id }),
  useRouter: () => ({ push: vi.fn() }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

import FindingIdLayout from '../layout'

describe('finding id layout', () => {
  beforeEach(() => {
    id = 'imports'
  })

  it('shows not-found for a segment that is not a UUID', () => {
    render(
      <FindingIdLayout>
        <div>detail page</div>
      </FindingIdLayout>
    )
    expect(screen.getByText('Finding not found')).toBeInTheDocument()
    expect(screen.queryByText('detail page')).toBeNull()
  })

  it('renders the page for a UUID', () => {
    id = '3f2b8a52-8c1e-4b8e-9a43-0d6f1b1c7a10'
    render(
      <FindingIdLayout>
        <div>detail page</div>
      </FindingIdLayout>
    )
    expect(screen.getByText('detail page')).toBeInTheDocument()
  })
})
