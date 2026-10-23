import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { RelativeTime } from '../relative-time'
import {
  KeyValueList,
  LabelSegments,
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
  it('renders the items in one size, spaced not dotted, skipping empty ones', () => {
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
    // No glyph: a 12px gap separates, and a hidden ", " is what a screen reader
    // hears and what a copy carries.
    expect(line).toHaveClass('gap-x-3')
    expect(line.textContent).toMatch(/^Source: httpx, First seen .*ago$/)
    expect(line.textContent).not.toMatch(/[·•∙⋅]/) // separator-ok: asserts absence
    const hidden = line.querySelectorAll('.sr-only')
    expect(hidden).toHaveLength(1)
    expect(hidden[0].textContent).toBe(', ')
    // Nothing inside sets its own size.
    expect(line.querySelectorAll('[class*="text-xs"],[class*="text-sm"]')).toHaveLength(0)
  })

  it('renders nothing when every item is empty', () => {
    const { container } = render(<MetaLine items={[null, false, '']} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('MetaLine separators', () => {
  it('puts a hidden comma between every pair, none before the first or after the last', () => {
    render(<MetaLine items={['a', 'b', 'c']} />)
    const line = document.querySelector('[data-slot=meta-line]') as HTMLElement
    expect(line.textContent).toBe('a, b, c')
    expect(line.querySelectorAll('.sr-only')).toHaveLength(2)
    expect(line.querySelector('[aria-hidden]')).toBeNull()
  })

  it('shows a single item with no separator', () => {
    render(<MetaLine items={['only', null]} />)
    expect(document.querySelector('[data-slot=meta-line]')?.textContent).toBe('only')
  })
})

describe('LabelSegments', () => {
  it('divides parts with a rule and reads as "key: value"', () => {
    render(<LabelSegments segments={['env', 'production']} />)
    const el = document.querySelector('[data-slot=label-segments]') as HTMLElement
    expect(el.textContent).toBe('env: production')
    expect(el.textContent).not.toMatch(/[·•∙⋅|]/) // separator-ok: asserts absence
    expect(screen.getByText('production')).toHaveClass('border-l')
    expect(screen.getByText('env')).not.toHaveClass('border-l')
  })

  it('uses the given hidden separator and skips empty segments', () => {
    render(<LabelSegments segments={['KEV', null, 'Past due']} srSeparator=", " />)
    expect(document.querySelector('[data-slot=label-segments]')?.textContent).toBe('KEV, Past due')
  })

  it('renders nothing without segments', () => {
    const { container } = render(<LabelSegments segments={[null, false]} />)
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
