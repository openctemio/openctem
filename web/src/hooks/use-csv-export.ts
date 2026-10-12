'use client'

import { useCallback } from 'react'
import { toast } from 'sonner'

export interface ExportFieldConfig<T> {
  /** Column header in the CSV */
  header: string
  /** Function to extract value from item */
  accessor: (item: T) => unknown
  /** Optional transform for display */
  transform?: (value: unknown) => string
}

/**
 * Sanitize a CSV cell to prevent formula injection.
 * Prefixes cells starting with =, +, -, @, \t, \r with a single quote.
 * Wraps cells containing commas, quotes, or newlines in double quotes.
 */
export function sanitizeCsvCell(value: unknown): string {
  let str = String(value ?? '')
  // Prevent formula injection (OWASP CSV injection): prefix a single quote when
  // the cell begins with a formula trigger (optionally after leading whitespace).
  if (/^\s*[=+\-@\t\r]/.test(str)) {
    str = `'${str}`
  }
  // Escape quotes and wrap when the value contains a delimiter, quote, or
  // newline. This MUST run even for formula-prefixed cells — otherwise a value
  // like "-a, b" or "@team, ops" gets the quote prefix but leaks its comma/
  // newline into the grid, shifting every following column/row.
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

/**
 * Build CSV text from a header row and data rows, every cell (headers too)
 * passed through sanitizeCsvCell. Use this instead of joining cells with ','
 * by hand: names, titles and versions come from scanners and SBOMs, so a cell
 * like `=HYPERLINK(...)` must not reach a spreadsheet as a formula, and a
 * comma or quote must not shift the columns.
 */
export function buildCsv(
  headers: readonly unknown[],
  rows: readonly (readonly unknown[])[]
): string {
  return [headers, ...rows].map((row) => row.map(sanitizeCsvCell).join(',')).join('\n')
}

/** Download CSV text as a file (UTF-8 BOM for Excel) and release the blob URL. */
export function downloadCsv(csv: string, filename: string): void {
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

/**
 * Generic, reusable CSV export hook.
 *
 * Generates a sanitized CSV (formula-injection safe) with a UTF-8 BOM for
 * Excel compatibility, triggers a download, and revokes the blob URL to avoid
 * a memory leak. Used by list pages and the
 * exposures page; reach for this whenever a list view needs "Export to CSV".
 */
/**
 * Build a sanitized CSV from an explicit dataset and trigger a download.
 * Standalone (not a hook) so callers can export a dynamically-fetched dataset
 * \u2014 e.g. "export ALL rows" by fetching every page first, rather than only the
 * page currently rendered. Returns false (and toasts) when there is nothing to
 * export.
 */
export function exportToCsv<T>(
  data: T[],
  fields: ExportFieldConfig<T>[],
  filename: string
): boolean {
  if (!data?.length) {
    toast.error('No data to export')
    return false
  }

  // Sanitize headers too, not just cells: a header sourced from user-defined
  // data (e.g. a custom field name) starting with =/+/-/@ would otherwise be
  // a formula-injection vector when the CSV is opened in a spreadsheet.
  const csv = buildCsv(
    fields.map((f) => f.header),
    data.map((item) =>
      fields.map((f) => {
        const raw = f.accessor(item)
        return f.transform ? f.transform(raw) : raw
      })
    )
  )
  downloadCsv(csv, `${filename}-${new Date().toISOString().slice(0, 10)}.csv`)
  toast.success(`Exported ${data.length} row${data.length === 1 ? '' : 's'}`)
  return true
}

/**
 * Generic, reusable CSV export hook. Exports the `data` passed in (the caller's
 * current dataset). For "export everything" use `exportToCsv` with a
 * fully-fetched dataset \u2014 passing only the current page here exports only that
 * page.
 */
export function useCsvExport<T>(data: T[], fields: ExportFieldConfig<T>[], filename: string) {
  const handleExport = useCallback(() => {
    exportToCsv(data, fields, filename)
  }, [data, fields, filename])

  return { handleExport }
}
