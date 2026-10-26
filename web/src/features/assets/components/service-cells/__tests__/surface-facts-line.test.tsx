import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import type { Asset } from '../../../types'
import { HttpStatusChip, SurfaceFactsLine } from '..'

/**
 * The list's one-line service facts fold by measured width: whole chips in
 * priority order, the rest in "+N", never a chip cut by the cell. jsdom has
 * no layout, so the line's width and each chip's width are stubbed.
 */

const edge = {
  id: 'a1',
  name: 'https://edge.example.com',
  type: 'service',
  subType: 'http',
  metadata: {
    status_code: 301,
    port: 443,
    protocol: 'https',
    scheme: 'https',
    cdn: 'Cloudflare',
    ip_addresses: ['162.159.140.229', '172.66.0.227'],
  },
  technologies: [{ name: 'nginx', version: '1.25.3', category: 'web_server' }],
} as unknown as Asset

// Widths by fit key: what a browser draws for these chips.
const CHIP_WIDTH: Record<string, number> = {
  status: 36,
  port: 81,
  edge: 125,
  'tech:nginx': 90,
}
let lineWidth = 0
const saved = {
  client: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth'),
  offset: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth'),
}

beforeEach(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientWidth', {
    configurable: true,
    get(this: HTMLElement) {
      return this.dataset.testid === 'surface-facts-line' ? lineWidth : 0
    },
  })
  Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
    configurable: true,
    get(this: HTMLElement) {
      const key = this.dataset.fitKey
      return key ? (CHIP_WIDTH[key] ?? 120) : 0
    },
  })
})

afterEach(() => {
  if (saved.client) Object.defineProperty(HTMLElement.prototype, 'clientWidth', saved.client)
  if (saved.offset) Object.defineProperty(HTMLElement.prototype, 'offsetWidth', saved.offset)
})

const shownKeys = (line: HTMLElement) =>
  [...line.querySelectorAll<HTMLElement>('[data-fit-key]')].map((el) => el.dataset.fitKey)

describe('SurfaceFactsLine (measured fold)', () => {
  it('a 256px cell: status code and port, then "+N" with every other fact', () => {
    lineWidth = 256
    render(<SurfaceFactsLine asset={edge} />)
    const line = screen.getByTestId('surface-facts-line')
    // 36 + 4 + 81 + 4 + 40 = 165; the edge chip (125) would need 294.
    expect(shownKeys(line)).toEqual(['status', 'port'])
    // edge, nginx, two IPs, TLS
    expect(within(line).getByRole('button', { name: '5 more facts' })).toHaveTextContent('+5')
  })

  it('a wider cell shows more whole chips, still in priority order', () => {
    lineWidth = 300
    render(<SurfaceFactsLine asset={edge} />)
    const line = screen.getByTestId('surface-facts-line')
    expect(shownKeys(line)).toEqual(['status', 'port', 'edge'])
    expect(within(line).getByRole('button', { name: '4 more facts' })).toBeInTheDocument()
  })

  it('a cell too narrow for the status shows only "+N", never a cut chip', () => {
    lineWidth = 60
    render(<SurfaceFactsLine asset={edge} />)
    const line = screen.getByTestId('surface-facts-line')
    expect(shownKeys(line)).toEqual([])
    expect(within(line).getByRole('button', { name: '7 more facts' })).toBeInTheDocument()
  })

  it('no chip can shrink below its content: every shown chip is shrink-0', () => {
    lineWidth = 256
    render(<SurfaceFactsLine asset={edge} />)
    const line = screen.getByTestId('surface-facts-line')
    for (const el of line.querySelectorAll('[data-fit-key]')) {
      expect(el.className).toContain('shrink-0')
    }
  })

  it('the status is its code; the reason phrase is read to screen readers', () => {
    lineWidth = 256
    render(<SurfaceFactsLine asset={edge} />)
    const chip = screen.getByTestId('surface-facts-line').querySelector('[data-status="301"]')!
    expect(chip).toHaveAttribute('data-slot', 'fact-chip')
    expect(chip).toHaveAttribute('data-tone', 'info')
    expect(chip.querySelector('.sr-only')?.textContent).toBe('Moved Permanently')
  })

  it('"+N" opens every fact: status with its phrase, edge, both addresses, the technology', () => {
    lineWidth = 256
    render(<SurfaceFactsLine asset={edge} />)
    fireEvent.click(screen.getByRole('button', { name: '5 more facts' }))
    const dialog = screen.getByRole('dialog', { name: 'Service facts' })
    expect(within(dialog).getByText('Moved Permanently')).toBeInTheDocument()
    expect(within(dialog).getByText('Behind Cloudflare')).toBeInTheDocument()
    expect(within(dialog).getByText('162.159.140.229')).toBeInTheDocument()
    expect(within(dialog).getByText('172.66.0.227')).toBeInTheDocument()
    expect(within(dialog).getByText(/nginx/i)).toBeInTheDocument()
  })

  it('without layout (width 0) every fact up to `max` shows', () => {
    lineWidth = 0
    render(<SurfaceFactsLine asset={edge} max={3} />)
    const line = screen.getByTestId('surface-facts-line')
    expect(shownKeys(line)).toEqual(['status', 'port', 'edge'])
  })
})

describe('HttpStatusChip compact', () => {
  it('shows the code only, coloured by class; the chain is read too', () => {
    render(<HttpStatusChip status={200} chain={[301]} compact />)
    const chip = document.querySelector('[data-status="200"]')!
    expect(chip).toHaveAttribute('data-tone', 'success')
    expect(chip.textContent).toBe('200OK, 301 → 200')
    expect(chip.querySelector('.sr-only')?.textContent).toBe('OK, 301 → 200')
  })
})
