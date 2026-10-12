import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const ID = 'dcdc3001-0000-0000-0000-000000000006'
const pathname = vi.hoisted(() => ({ current: '' }))
vi.mock('next/navigation', () => ({ usePathname: () => pathname.current }))

const { BreadcrumbNav } = await import('../breadcrumb-nav')
const { useBreadcrumbTitle } = await import('../breadcrumb-title')

function DetailPage({ title, path }: { title: string | null; path?: string }) {
  useBreadcrumbTitle(title, path)
  return null
}

const UUID_TEXT = /[0-9a-f]{8}(-|\.\.\.)/

describe('useBreadcrumbTitle', () => {
  it('shows the record kind until the page names itself, never the id', () => {
    pathname.current = `/findings/${ID}`
    const { rerender } = render(
      <>
        <BreadcrumbNav />
        <DetailPage title={null} />
      </>
    )
    expect(screen.getByText('Finding')).toBeInTheDocument()
    expect(screen.queryByText(UUID_TEXT)).not.toBeInTheDocument()

    rerender(
      <>
        <BreadcrumbNav />
        <DetailPage title="CVE-2024-21538 · cross-spawn" />
      </>
    )
    expect(screen.getByText('CVE-2024-21538 · cross-spawn')).toBeInTheDocument()
    expect(screen.queryByText('Finding')).not.toBeInTheDocument()
  })

  it('drops the name when the page unmounts', () => {
    pathname.current = `/findings/${ID}`
    const { rerender } = render(
      <>
        <BreadcrumbNav />
        <DetailPage title="CVE-2024-21538 · cross-spawn" />
      </>
    )
    rerender(<BreadcrumbNav />)
    expect(screen.getByText('Finding')).toBeInTheDocument()
  })

  it('names an id in the middle of the path (a sub-page of a record)', () => {
    pathname.current = `/settings/pentest/templates/${ID}/edit`
    const { rerender } = render(
      <>
        <BreadcrumbNav />
        <DetailPage title={null} />
      </>
    )
    expect(screen.getByText('Template')).toBeInTheDocument()
    expect(screen.getByText('Edit')).toBeInTheDocument()
    expect(screen.queryByText(UUID_TEXT)).not.toBeInTheDocument()

    rerender(
      <>
        <BreadcrumbNav />
        <DetailPage title="Web app baseline" path={`/settings/pentest/templates/${ID}`} />
      </>
    )
    expect(screen.getByText('Web app baseline')).toBeInTheDocument()
    expect(screen.queryByText('Template')).not.toBeInTheDocument()
  })

  it('falls back to "Details" under a parent with no record kind', () => {
    pathname.current = `/something-new/${ID}`
    render(<BreadcrumbNav />)
    expect(screen.getByText('Details')).toBeInTheDocument()
    expect(screen.queryByText(UUID_TEXT)).not.toBeInTheDocument()
  })
})
