import { describe, it, expect } from 'vitest'
import {
  Bot,
  BotMessageSquare,
  Brain,
  BrainCircuit,
  Sparkle,
  Sparkles,
  Stars,
  Wand,
  Wand2,
  WandSparkles,
} from 'lucide-react'
import * as config from '@/config/section-tabs'
import { stripIconsAllowed, type SectionTab } from '../section-tabs'

/**
 * The tab icon rule (research/244 D3, as amended by the owner): icons on tabs
 * are optional, but a strip has them on every tab or on none, each icon is
 * distinct within its strip and says what the tab holds. Generic "magic"
 * icons read as decoration and are refused.
 */
const GENERIC = new Set<unknown>([
  Sparkles,
  Sparkle,
  Stars,
  Wand,
  Wand2,
  WandSparkles,
  Bot,
  BotMessageSquare,
  Brain,
  BrainCircuit,
])

const strips = Object.entries(config).filter(
  (e): e is [string, readonly SectionTab[]] =>
    e[0].endsWith('_TABS') &&
    Array.isArray(e[1]) &&
    e[1].every((t: unknown) => typeof t === 'object' && t !== null && 'href' in t)
)

describe('section tab icons', () => {
  it('finds the strips', () => {
    expect(strips.length).toBeGreaterThan(5)
  })

  it.each(strips)('%s: every tab has a distinct icon, or none has', (_, tabs) => {
    const withIcon = tabs.filter((t) => t.icon).length
    if (withIcon === 0) return
    expect(withIcon, 'all or none').toBe(tabs.length)
    expect(stripIconsAllowed(tabs), 'no icon repeats within the strip').toBe(true)
  })

  it.each(strips)('%s: no generic decoration icon', (_, tabs) => {
    for (const t of tabs) expect(GENERIC.has(t.icon), t.label).toBe(false)
  })
})
