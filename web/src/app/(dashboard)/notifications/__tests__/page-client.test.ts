import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// The page uses hooks and context, so it must be a client component. Without
// the directive the route rendered the error boundary ("Something went wrong").
describe('notifications page', () => {
  it('is a client component', () => {
    const src = readFileSync(join(__dirname, '..', 'page.tsx'), 'utf8')
    expect(src.trimStart().startsWith("'use client'")).toBe(true)
  })

  it('stacks its blocks in a PageStack', () => {
    const src = readFileSync(join(__dirname, '..', 'page.tsx'), 'utf8')
    expect(src).toContain('<PageStack>')
  })
})
