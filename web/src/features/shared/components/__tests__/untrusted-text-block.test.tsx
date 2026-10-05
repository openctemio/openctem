import { describe, it, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { act, fireEvent, render, screen } from '@testing-library/react'

const copy = vi.hoisted(() => vi.fn(async () => true))
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: copy }))

const { UntrustedTextBlock } = await import('../untrusted-text-block')

const RLO = String.fromCodePoint(0x202e)
const ESC = String.fromCodePoint(0x1b)
const HOSTILE = `Server: <script>alert(1)</script>\n${ESC}[31mred${ESC}[0m ${RLO}gnp.exe\r\n[link](javascript:alert(1))`

describe('UntrustedTextBlock (scanner output)', () => {
  it('renders markup, ANSI and bidi characters literally, never as HTML', () => {
    const { container } = render(<UntrustedTextBlock text={HOSTILE} label="Scanner output" />)
    const pre = screen.getByTestId('untrusted-text-block')
    expect(pre.tagName).toBe('PRE')
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('a')).toBeNull()
    expect(pre.textContent).toContain('<script>alert(1)</script>')
    expect(pre.textContent).toContain('[link](javascript:alert(1))')
    // Control and direction characters are visible escapes, not applied.
    expect(pre.textContent).not.toContain(RLO)
    expect(pre.textContent).not.toContain(ESC)
    expect(pre.textContent).toContain('\\u{202E}')
    expect(pre.textContent).toContain('\\u{001B}[31m')
    // Line breaks are kept (a block, not one line).
    expect(pre.textContent).toContain('alert(1)</script>\n')
    expect(pre).toHaveAttribute('dir', 'ltr')
    expect(screen.getByText(/shown as escapes/)).toBeInTheDocument()
  })

  it('Copy copies the raw text, not the escaped view', async () => {
    render(<UntrustedTextBlock text={HOSTILE} label="Scanner output" />)
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy scanner output' }))
    })
    expect(copy).toHaveBeenCalledWith(HOSTILE)
  })

  it('has no dangerouslySetInnerHTML in the component or the output section', () => {
    for (const f of [
      join(__dirname, '..', 'untrusted-text-block.tsx'),
      join(__dirname, '..', '..', '..', 'findings', 'components', 'detail', 'overview-tab.tsx'),
    ]) {
      expect(readFileSync(f, 'utf8')).not.toContain('dangerouslySetInnerHTML')
    }
  })
})
