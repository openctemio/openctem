/**
 * AssetPeekLink (research/353 D6): a plain click opens the asset's drawer
 * over the list; a modified click, or a click outside the provider, follows
 * the link to the asset page; a value that is not an asset id is plain text.
 * The drawer only shows the asset the API answered for that id.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const ID = '0198f0e2-4444-7000-8000-000000000004'
const reads = vi.hoisted(() => ({ ids: [] as (string | null)[] }))
vi.mock('../../hooks/use-assets', () => ({
  useAsset: (id: string | null) => {
    reads.ids.push(id)
    return { asset: id ? { id, name: 'peeked.example.com' } : null, isLoading: false }
  },
}))
vi.mock('../asset-detail-sheet', () => ({
  AssetDetailSheet: ({ asset, open }: { asset: { name: string } | null; open: boolean }) =>
    open && asset ? <div role="dialog" aria-label={asset.name} /> : null,
}))

const { AssetPeekLink, AssetPeekProvider } = await import('../asset-peek')

beforeEach(() => {
  reads.ids = []
})

describe('AssetPeekLink', () => {
  it('opens the drawer on a plain click and keeps the page link', () => {
    render(
      <AssetPeekProvider>
        <AssetPeekLink assetId={ID}>peeked.example.com</AssetPeekLink>
      </AssetPeekProvider>
    )
    const link = screen.getByRole('link', { name: 'peeked.example.com' })
    expect(link).toHaveAttribute('href', `/assets/${ID}`)
    expect(screen.queryByRole('dialog')).toBeNull()
    // Nothing is read before the reader asks for it.
    expect(reads.ids.every((id) => id === null)).toBe(true)
    fireEvent.click(link)
    expect(screen.getByRole('dialog', { name: 'peeked.example.com' })).toBeInTheDocument()
    expect(reads.ids).toContain(ID)
  })

  it('lets a modified click open the page in a new tab', () => {
    render(
      <AssetPeekProvider>
        <AssetPeekLink assetId={ID}>peeked.example.com</AssetPeekLink>
      </AssetPeekProvider>
    )
    const link = screen.getByRole('link', { name: 'peeked.example.com' })
    const event = new MouseEvent('click', { bubbles: true, cancelable: true, ctrlKey: true })
    link.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(false)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('is a plain link outside a provider', () => {
    render(<AssetPeekLink assetId={ID}>peeked.example.com</AssetPeekLink>)
    const link = screen.getByRole('link', { name: 'peeked.example.com' })
    const event = new MouseEvent('click', { bubbles: true, cancelable: true })
    link.dispatchEvent(event)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('renders text for a value that is not an asset id', () => {
    render(
      <AssetPeekProvider>
        <AssetPeekLink assetId="old.example.com">old.example.com</AssetPeekLink>
        <AssetPeekLink assetId="00000000-0000-0000-0000-000000000000">nil</AssetPeekLink>
      </AssetPeekProvider>
    )
    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText('old.example.com')).toBeInTheDocument()
  })
})

/**
 * One way to open an asset across the attack surface views: rows use
 * AssetPeekLink, never a hand-built link to the asset page.
 */
// Views still in open pull requests when this gate landed; each moves to
// AssetPeekLink after it merges (research/353 migration plan). Never add one.
const PENDING = new Set(['easm-posture.tsx', 'easm-exposure-items.tsx'])

describe('attack surface rows', () => {
  it('open assets through AssetPeekLink', () => {
    const dir = join(__dirname, '../../../attack-surface/components')
    const offenders = readdirSync(dir)
      .filter((f) => f.endsWith('.tsx') && !PENDING.has(f))
      .filter((f) => {
        const src = readFileSync(join(dir, f), 'utf8')
        return /assetDetailHref\(|href=\{`\/assets\/\$\{/.test(src)
      })
    expect(offenders).toEqual([])
  })
})
