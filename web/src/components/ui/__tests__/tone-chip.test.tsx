import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Globe } from 'lucide-react'
import { TONE_CLASS, ToneChip, type Tone } from '../tone-chip'
import { LEVEL_CLASS, Tag } from '../tag'

describe('ToneChip (research/266)', () => {
  const TONES: Tone[] = ['danger', 'caution', 'ok', 'info', 'neutral', 'quiet']

  it.each(TONES)('%s: tinted with its own text colour, word always shown', (tone) => {
    render(<ToneChip tone={tone} icon={Globe} label="Public" title="hint" value="public" />)
    const el = screen.getByText('Public').closest('[data-slot="tone-chip"]') as HTMLElement
    expect(el.dataset.tone).toBe(tone)
    expect(el.dataset.value).toBe('public')
    for (const c of TONE_CLASS[tone].split(' ')) expect(el.className).toContain(c)
    // The icon is decorative; the word names the value.
    expect(el.querySelector('svg')).toHaveAttribute('aria-hidden')
    expect(el.title).toBe('hint')
  })

  it('every tone has a distinct tint, and no tone uses a /N opacity tint', () => {
    const tints = TONES.map((t) => TONE_CLASS[t].split(' ')[0])
    expect(new Set(tints).size).toBe(TONES.length)
    for (const t of TONES) expect(TONE_CLASS[t]).not.toMatch(/\/\d+/)
  })

  it('dashed marks an unknown value', () => {
    render(<ToneChip tone="quiet" label="Unknown" dashed />)
    expect(screen.getByText('Unknown').closest('[data-slot="tone-chip"]')?.className).toContain(
      'border-dashed'
    )
  })
})

describe('Tag levels: brand ink by weight (research/266)', () => {
  it.each([4, 3, 2, 1, 0] as const)('level %s gets its own fill and text', (level) => {
    render(<Tag label={`L${level}`} level={level} />)
    const el = screen.getAllByText(`L${level}`)[0].closest('[data-slot="tag"]') as HTMLElement
    for (const c of LEVEL_CLASS[level].split(' ')) expect(el.className).toContain(c)
  })

  it('the solid level wins over the neutral pill colours', () => {
    render(<Tag label="Critical" level={4} />)
    const el = screen.getAllByText('Critical')[0].closest('[data-slot="tag"]') as HTMLElement
    expect(el.className).not.toMatch(/(^|\s)bg-card(\s|$)/)
    expect(el.className).not.toMatch(/(^|\s)text-foreground(\s|$)/)
  })
})
