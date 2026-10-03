import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const pathname = vi.hoisted(() => ({ current: '/findings/dcdc3001-0000-0000-0000-000000000006' }))
vi.mock('next/navigation', () => ({ usePathname: () => pathname.current }))

const { BreadcrumbNav } = await import('../breadcrumb-nav')
const { useBreadcrumbTitle } = await import('../breadcrumb-title')

function DetailPage({ title }: { title: string | null }) {
  useBreadcrumbTitle(title)
  return null
}

describe('useBreadcrumbTitle', () => {
  it('shows the shortened ID until the page names itself', () => {
    const { rerender } = render(
      <>
        <BreadcrumbNav />
        <DetailPage title={null} />
      </>
    )
    expect(screen.getByText('dcdc3001...')).toBeInTheDocument()

    rerender(
      <>
        <BreadcrumbNav />
        <DetailPage title="CVE-2024-21538 · cross-spawn" />
      </>
    )
    expect(screen.getByText('CVE-2024-21538 · cross-spawn')).toBeInTheDocument()
    expect(screen.queryByText('dcdc3001...')).not.toBeInTheDocument()
  })

  it('drops the name when the page unmounts', () => {
    const { rerender } = render(
      <>
        <BreadcrumbNav />
        <DetailPage title="CVE-2024-21538 · cross-spawn" />
      </>
    )
    rerender(<BreadcrumbNav />)
    expect(screen.getByText('dcdc3001...')).toBeInTheDocument()
  })
})
