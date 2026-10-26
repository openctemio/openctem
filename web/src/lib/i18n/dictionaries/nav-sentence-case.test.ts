import { describe, expect, it } from 'vitest'
import nav from './en/nav.json'

// Product and acronym words that keep their capital inside a sentence-case label.
const PROPER = new Set(['K8s', 'Microsoft', 'GitHub', 'GitLab', 'Jira', 'Slack', 'Entra', 'Okta'])

describe('sidebar labels are sentence case', () => {
  it('only the first word of an en nav.item label is capitalised (acronyms and product names aside)', () => {
    const bad = Object.entries(nav as Record<string, string>)
      .filter(([k]) => k.startsWith('nav.item.'))
      .filter(([, v]) =>
        v
          .split(' ')
          .slice(1)
          .some((w) => /^[A-Z][a-z]/.test(w) && !PROPER.has(w))
      )
      .map(([k, v]) => `${k}: ${v}`)
    expect(bad).toEqual([])
  })
})
