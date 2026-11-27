import fs from 'node:fs'
import path from 'node:path'
import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ScreenReaderTable } from '../screen-reader-table'

const SRC_ROOT = path.resolve(__dirname, '../..')

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) {
      if (e.name !== 'node_modules' && e.name !== '__tests__') out.push(...sourceFiles(p))
    } else if (/\.tsx$/.test(e.name) && !/\.test\.tsx$/.test(e.name)) out.push(p)
  }
  return out
}

describe('ScreenReaderTable', () => {
  it('clips the table inside a visually hidden box, keeping the table itself', () => {
    const { container } = render(
      <ScreenReaderTable>
        <caption>Exposure over time</caption>
        <tbody>
          <tr>
            <td>1 Nov</td>
            <td>12</td>
          </tr>
        </tbody>
      </ScreenReaderTable>
    )
    const box = container.firstElementChild as HTMLElement
    expect(box.tagName).toBe('DIV')
    expect(box).toHaveClass('sr-only')
    const table = box.querySelector('table')!
    expect(table).not.toHaveClass('sr-only')
    expect(table.querySelector('caption')).toHaveTextContent('Exposure over time')
  })

  // A table does not shrink to the 1px box of `sr-only`: each of its rows
  // makes the page scroll further past its last content.
  it('is the only way a hidden table is written', () => {
    const offenders: string[] = []
    for (const file of sourceFiles(SRC_ROOT)) {
      const text = fs.readFileSync(file, 'utf8')
      if (/<table\b[^>]*\bsr-only\b/.test(text)) offenders.push(path.relative(SRC_ROOT, file))
    }
    expect(offenders).toEqual([])
  })
})
