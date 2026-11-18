/**
 * List first on a phone (acceptance review K35): a metric strip above a list
 * moves under it on a phone, so the first row starts within the top 45% of a
 * 390x844 screen. The move is CSS order (`listFirst`), never a JS phone
 * check, so nothing jumps after hydration.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { MetricStrip } from '../metric-strip'

const SRC = join(__dirname, '..', '..', '..', '..')

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : sources(path)
    return /\.tsx$/.test(name) && !/\.(test|stories)\.tsx$/.test(name) ? [path] : []
  })
}

describe('MetricStrip listFirst', () => {
  it('orders the strip after the list below the md breakpoint', () => {
    const { container } = render(
      <MetricStrip items={[{ key: 'runs', label: 'Runs', value: 3 }]} listFirst />
    )
    expect(container.querySelector('[data-slot="metric-strip"]')).toHaveClass('max-md:order-last')
  })

  it('every list page puts its strip after the list on a phone (or hides it there)', () => {
    const offenders = sources(SRC)
      .filter((file) => {
        const s = readFileSync(file, 'utf8')
        return s.includes('<MetricStrip') && s.includes('<ListTitleRow')
      })
      .flatMap((file) => {
        const s = readFileSync(file, 'utf8')
        const tags = s.match(/<MetricStrip\b[^>]*?\/>/g) ?? []
        return tags
          .filter((tag) => !/\blistFirst\b|max-md:hidden/.test(tag))
          .map(() => relative(SRC, file))
      })
    expect(offenders).toEqual([])
  })
})
