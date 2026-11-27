import type { TableHTMLAttributes } from 'react'

/**
 * A data table only screen readers read (the numbers behind a chart).
 *
 * `sr-only` on the <table> itself does not hide its size: a table box grows to
 * its rows whatever its width and height, and `overflow: hidden` does not clip
 * a table. The absolutely placed table then made its scroll container one row
 * taller per data point (a 90-day trend left a screen of empty scroll below
 * the last card on a phone). The clipping box is a wrapper, so the table takes
 * no room at all.
 */
export function ScreenReaderTable(props: TableHTMLAttributes<HTMLTableElement>) {
  return (
    <div className="sr-only">
      <table {...props} />
    </div>
  )
}
