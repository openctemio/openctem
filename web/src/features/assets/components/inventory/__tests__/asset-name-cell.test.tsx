/**
 * The inventory Name cell: long names cut in the middle (both ends kept), a
 * copy button that copies the full name, a certificate read by its subject
 * name with the asset name below, and discovered values drawn as text.
 */
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { AssetNameCell, NAME_MAX } from '../asset-name-cell'
import type { Asset } from '../../../types'

vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
  useLinkStatus: () => ({ pending: false }),
}))
const copied: string[] = []
vi.mock('@/lib/clipboard', () => ({
  copyToClipboard: async (s: string) => {
    copied.push(s)
    return true
  },
}))

const asset = (over: Partial<Asset>): Asset =>
  ({ id: 'a1', name: 'x', type: 'domain', metadata: {}, tags: [], ...over }) as Asset

function cell(a: Asset, onOpen = vi.fn()) {
  render(
    <TooltipProvider>
      <AssetNameCell asset={a} href={`/assets/${a.id}`} onOpen={onOpen} />
    </TooltipProvider>
  )
  return onOpen
}

describe('AssetNameCell', () => {
  it('cuts a long name in the middle, keeping both ends, with the full name as its label', () => {
    const name = 'sha256:9f2c4e1a7b3d8e0f5a6c2b9d4e7f1a3c8b5d0e2f6a9c4b7d1e3f8a5c0b2d6e9f'
    cell(asset({ name, type: 'service' }))
    const link = screen.getByRole('link', { name })
    expect(link).toHaveAttribute('href', '/assets/a1')
    const shown = link.textContent ?? ''
    expect(Array.from(shown)).toHaveLength(NAME_MAX)
    expect(shown.startsWith('sha256:9f2c')).toBe(true)
    expect(shown.endsWith('c0b2d6e9f')).toBe(true)
    expect(shown).toContain('…')
  })

  it('a short name is shown whole', () => {
    cell(asset({ name: 'mail.example.com' }))
    expect(screen.getByRole('link', { name: 'mail.example.com' })).toHaveTextContent(
      'mail.example.com'
    )
  })

  it('copies the full name without opening the row', async () => {
    const onOpen = cell(asset({ name: 'api.example.com:443' }))
    fireEvent.click(screen.getByRole('button', { name: 'Copy api.example.com:443' }))
    await screen.findByRole('button', { name: 'Copied' })
    expect(copied).toContain('api.example.com:443')
    expect(onOpen).not.toHaveBeenCalled()
  })

  it('a certificate shows its subject name, with the asset name below', () => {
    cell(
      asset({
        type: 'certificate',
        name: 'sha256:4be1a0c977d2e0f13aa',
        metadata: { subject_cn: '*.shop.example.com', sans: 'shop.example.com,www.example.com' },
      })
    )
    const link = screen.getByRole('link')
    expect(link).toHaveTextContent('*.shop.example.com')
    expect(screen.getByText('sha256:4be1a0c977d2e0f13aa')).toBeInTheDocument()
  })

  it('draws a hostile name as text', () => {
    cell(asset({ name: '<img src=x onerror=alert(1)>' }))
    const c = screen.getByTestId('asset-name-cell')
    expect(c.querySelector('img')).toBeNull()
    expect(c.textContent).toContain('<img')
  })
})
