import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { RelativeTime } from '../relative-time'
import {
  KeyValueList,
  ListItem,
  MetaItem,
  MetaLine,
  TokenText,
  middleTruncate,
} from '../text-layout'

describe('type scale', () => {
  it('keeps a type-scale size next to a colour when classes merge', () => {
    expect(cn('text-meta', 'text-muted-foreground')).toBe('text-meta text-muted-foreground')
    // A later size still replaces an earlier one.
    expect(cn('text-sm', 'text-meta')).toBe('text-meta')
  })

  it('lets RelativeTime take the size of the line it sits in', () => {
    render(<RelativeTime date={new Date(Date.now() - 3_600_000).toISOString()} />)
    const el = screen.getByText(/ago/)
    expect(el.className).not.toMatch(/text-(xs|sm|base)/)
    expect(el).toHaveAttribute('title')
  })
})

describe('MetaLine', () => {
  it('renders the items in one size, dot-separated, skipping empty ones', () => {
    render(
      <MetaLine
        items={[
          'Source: httpx',
          null,
          <MetaItem key="f" label="First seen">
            <RelativeTime date={new Date(Date.now() - 3_600_000).toISOString()} />
          </MetaItem>,
        ]}
      />
    )
    const line = document.querySelector('[data-slot=meta-line]') as HTMLElement
    expect(line).toHaveClass('text-meta')
    expect(line.textContent).toMatch(/^Source: httpx·First seen .*ago$/)
    // Nothing inside sets its own size.
    expect(line.querySelectorAll('[class*="text-xs"],[class*="text-sm"]')).toHaveLength(0)
  })

  it('renders nothing when every item is empty', () => {
    const { container } = render(<MetaLine items={[null, false, '']} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('ListItem', () => {
  it('gives the name its own line with a basis, so it is never squeezed', () => {
    render(
      <ul>
        <ListItem title="Cloudflare" trailing={<span>CDN</span>} meta={['Source: httpx']} />
      </ul>
    )
    const name = screen.getByText('Cloudflare')
    expect(name).toHaveClass('min-w-0', 'flex-1', 'basis-40', 'break-words')
    expect(name.className).not.toMatch(/break-all|overflow-wrap:anywhere/)
    expect(screen.getByText('Source: httpx').closest('[data-slot=meta-line]')).toBeInTheDocument()
  })
})

describe('KeyValueList', () => {
  it('uses one size for labels and values, the label muted', () => {
    render(
      <KeyValueList
        size="meta"
        items={[
          { key: 'src', label: 'Source', value: 'httpx' },
          { key: 'sha', label: 'SHA-256', value: 'abc', token: true },
        ]}
      />
    )
    const dl = document.querySelector('[data-slot=key-value-list]') as HTMLElement
    expect(dl).toHaveClass('text-meta')
    expect(screen.getByText('Source')).toHaveClass('text-muted-foreground')
    expect(screen.getByText('Source').className).not.toMatch(/text-(xs|sm)/)
    expect(screen.getByText('httpx')).toHaveClass('break-words')
    expect(screen.getByText('abc')).toHaveClass('font-mono')
  })
})

describe('TokenText', () => {
  it('cuts a long token in the middle and keeps the full value reachable', () => {
    const sha = 'a'.repeat(20) + 'MIDDLE' + 'b'.repeat(20)
    render(
      <TooltipProvider>
        <TokenText value={sha} max={16} />
      </TooltipProvider>
    )
    const short = middleTruncate(sha, 16)
    expect(short).toHaveLength(16)
    expect(short.startsWith('aaaa')).toBe(true)
    expect(short.endsWith('bbbb')).toBe(true)
    expect(screen.getByText(short)).toBeInTheDocument()
    expect(screen.getByLabelText(sha)).toBeInTheDocument()
  })

  it('leaves a short token whole with no tooltip', () => {
    render(<TokenText value="v1.2.3" />)
    expect(screen.getByText('v1.2.3')).toBeInTheDocument()
    expect(middleTruncate('v1.2.3')).toBe('v1.2.3')
  })
})
