/**
 * A field's placeholder that is longer than the field ends in an ellipsis,
 * never cut mid-word. Regression (acceptance review 2026-11-18): every list
 * search on a phone showed "Search findings by tit" with no mark that text was
 * cut. The browser draws the ellipsis from `text-overflow: ellipsis` on the
 * input; the e2e sweep measures it, this pins the class on the kit field and
 * on the list search built on it.
 */
import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { Input } from '../input'
import { ListSearch } from '@/features/shared/components/list-search'

describe('Input placeholder', () => {
  it('the kit field cuts with an ellipsis', () => {
    const { container } = render(<Input placeholder="Search findings by title, CVE or asset" />)
    expect(container.querySelector('input')?.className).toContain('text-ellipsis')
  })

  it('the list search field cuts with an ellipsis', () => {
    const { container } = render(
      <ListSearch
        value=""
        onChange={() => {}}
        placeholder="Search findings by title, CVE or asset"
      />
    )
    expect(container.querySelector('input')?.className).toContain('text-ellipsis')
  })
})
