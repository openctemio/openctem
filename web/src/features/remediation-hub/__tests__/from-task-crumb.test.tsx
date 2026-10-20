import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const params = new URLSearchParams()
const task: { data?: { title: string } } = {}
vi.mock('next/navigation', () => ({ useSearchParams: () => params }))
vi.mock('../api/use-remediation-hub', () => ({ useTask: () => task }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (k: string) => k }),
}))
vi.mock('@/components/link', () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}))

import { FromTaskCrumb } from '../components/from-task-crumb'

describe('FromTaskCrumb', () => {
  beforeEach(() => {
    params.delete('from')
    task.data = { title: 'Upgrade django' }
  })

  it('links back to the task the finding was opened from', () => {
    params.set('from', 'task:0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b')
    render(<FromTaskCrumb />)
    expect(screen.getByRole('link', { name: 'Upgrade django' }).getAttribute('href')).toBe(
      '/remediation/tasks/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
    )
  })

  it('renders nothing without a valid from, or when the task cannot be read', () => {
    const { container, rerender } = render(<FromTaskCrumb />)
    expect(container).toBeEmptyDOMElement()
    params.set('from', 'task:0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b')
    task.data = undefined
    rerender(<FromTaskCrumb />)
    expect(container).toBeEmptyDOMElement()
  })
})
