/**
 * ScannerText renders untrusted scanner prose: markdown without raw HTML,
 * scripts and commands as code blocks (Copy, Show more, Example output),
 * and no way for hostile text to run script, load an image or link to a
 * non-http URL.
 */

import { describe, it, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { act, fireEvent, render, screen } from '@testing-library/react'

const copy = vi.hoisted(() => vi.fn(async () => true))
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: copy }))

const { ScannerText, SCANNER_CODE_LINES } = await import('../scanner-text')

const SCRIPT = [
  'Run the following script:',
  '',
  '#!/usr/bin/env bash',
  '{',
  ...Array.from({ length: 30 }, (_, i) => `   echo "line ${i}"`),
  '}',
].join('\n')

describe('ScannerText: layout', () => {
  it('renders a script as a highlighted code block with Copy', async () => {
    const { container } = render(<ScannerText text={SCRIPT} />)
    expect(screen.getByText('Run the following script:')).toBeInTheDocument()
    const pre = screen.getByTestId('untrusted-text-block')
    expect(pre).toHaveAttribute('data-language', 'shell')
    // Highlighted: the keyword is its own token span.
    expect(container.querySelector('pre span')).not.toBeNull()
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy script' }))
    })
    expect(copy).toHaveBeenCalledWith(expect.stringMatching(/^#!\/usr\/bin\/env bash\n\{/))
  })

  it('collapses a long block to its first lines, with Show more', () => {
    render(<ScannerText text={SCRIPT} />)
    const pre = screen.getByTestId('untrusted-text-block')
    expect(pre.textContent!.split('\n')).toHaveLength(SCANNER_CODE_LINES)
    expect(pre.textContent).not.toContain('line 29')
    fireEvent.click(screen.getByRole('button', { name: /Show \d+ more lines/ }))
    expect(screen.getByTestId('untrusted-text-block').textContent).toContain('line 29')
    expect(screen.getByRole('button', { name: 'Show less' })).toBeInTheDocument()
  })

  it('shows what a command prints apart, as "Example output", and copies only the command', async () => {
    render(
      <ScannerText text={'$ sysctl kernel.randomize_va_space\nkernel.randomize_va_space = 2'} />
    )
    expect(screen.getByText('Example output')).toBeInTheDocument()
    expect(screen.getByText('Command')).toBeInTheDocument()
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy command' }))
    })
    expect(copy).toHaveBeenLastCalledWith('sysctl kernel.randomize_va_space')
  })

  it('wraps long tokens instead of scrolling the page sideways', () => {
    const refs = 'NESA|T1.2.1,'.repeat(60)
    const { container } = render(<ScannerText text={`Reference: ${refs}`} />)
    const prose = container.querySelector('[data-slot="scanner-text"] div div')!
    expect(prose.className).toContain('[overflow-wrap:anywhere]')
  })

  it('preview: clips long text with Show more', () => {
    const long = Array.from({ length: 20 }, (_, i) => `Paragraph ${i} of the advisory.`).join(
      '\n\n'
    )
    const { container } = render(<ScannerText text={long} preview />)
    expect(container.querySelector('[data-collapsed]')).not.toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Show more' }))
    expect(container.querySelector('[data-collapsed]')).toBeNull()
  })
})

describe('ScannerText: hostile text (XSS)', () => {
  const HOSTILE = [
    'Intro <script>alert(1)</script> and <img src=x onerror=alert(2)>',
    '',
    '<iframe src="https://example.com/x"></iframe>',
    '',
    '[click](javascript:alert(3)) [data](data:text/html;base64,PHNjcmlwdD4=) [vb](vbscript:msgbox)',
    '',
    '<javascript:alert(4)>',
    '',
    '![pixel](https://example.com/track.gif) ![x](javascript:alert(5))',
    '',
    '[ok](https://example.com/advisory)',
    '',
    '# Heading from the scanner',
    '',
    'Text<!--rehype:style=position:fixed;inset:0&class=fixed-->',
    '',
    `RTL ${String.fromCodePoint(0x202e)}gnp.exe`,
  ].join('\n')

  it('renders no script, image, iframe or event handler', () => {
    const { container } = render(<ScannerText text={HOSTILE} />)
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('iframe')).toBeNull()
    for (const el of Array.from(container.querySelectorAll('*'))) {
      for (const attr of Array.from(el.attributes)) {
        expect(attr.name.startsWith('on'), el.outerHTML).toBe(false)
      }
      expect(el.getAttribute('style'), el.outerHTML).toBeNull()
    }
  })

  it('shows raw HTML as the characters it is', () => {
    const { container } = render(<ScannerText text={HOSTILE} />)
    expect(container.textContent).toContain('<script>alert(1)</script>')
    expect(container.textContent).toContain('<iframe src="https://example.com/x"></iframe>')
  })

  it('links only http(s) URLs, in a new tab without an opener', () => {
    const { container } = render(<ScannerText text={HOSTILE} />)
    const links = Array.from(container.querySelectorAll('a'))
    expect(links.map((a) => a.getAttribute('href'))).toEqual(['https://example.com/advisory'])
    expect(links[0]).toHaveAttribute('target', '_blank')
    expect(links[0].getAttribute('rel')).toContain('noopener')
    expect(links[0].getAttribute('rel')).toContain('noreferrer')
    // The refused links keep their text.
    expect(screen.getByText('click')).toBeInTheDocument()
  })

  it('never loads an image the text names (alt text only)', () => {
    const { container } = render(<ScannerText text={HOSTILE} />)
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('pixel')).toBeInTheDocument()
  })

  it('renders a heading as a paragraph and makes bidi controls visible', () => {
    const { container } = render(<ScannerText text={HOSTILE} />)
    expect(container.querySelector('h1,h2,h3,h4,h5,h6')).toBeNull()
    expect(container.textContent).not.toContain(String.fromCodePoint(0x202e))
    expect(container.textContent).toContain('\\u{202E}')
  })

  it('a script tag inside a detected code block stays text', () => {
    const { container } = render(
      <ScannerText text={'$ echo "<script>alert(1)</script>"\n<img src=x onerror=alert(1)>'} />
    )
    expect(container.querySelector('script, img')).toBeNull()
    expect(container.textContent).toContain('<img src=x onerror=alert(1)>')
  })

  it('has no dangerouslySetInnerHTML and no raw-HTML plugin', () => {
    const src = readFileSync(join(__dirname, '..', 'scanner-text.tsx'), 'utf8')
    expect(src).not.toContain('dangerouslySetInnerHTML')
    expect(src).not.toMatch(/rehype-raw|rehypeRaw/)
  })
})
