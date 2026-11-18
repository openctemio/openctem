/**
 * Guard: a notice is announced as an alert only when it is an error. A static
 * notice, a warning or a success shown with role="alert" interrupts a screen
 * reader on every page load as if something had failed.
 */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { EntryBanner } from '@/components/entry/entry-card'

describe('notice roles', () => {
  it('announces only the destructive Alert as an alert', () => {
    render(
      <>
        <Alert data-testid="note">
          <AlertDescription>Scans pause at night.</AlertDescription>
        </Alert>
        <Alert variant="destructive" data-testid="error">
          <AlertDescription>The scan could not start.</AlertDescription>
        </Alert>
      </>
    )
    expect(screen.getByTestId('note')).toHaveAttribute('role', 'status')
    expect(screen.getByTestId('error')).toHaveAttribute('role', 'alert')
  })

  it('announces only the danger EntryBanner as an alert', () => {
    render(
      <>
        <EntryBanner tone="info" data-testid="info">
          Your session ended. Sign in again.
        </EntryBanner>
        <EntryBanner tone="warn" data-testid="warn">
          Only enter a code you asked for.
        </EntryBanner>
        <EntryBanner tone="ok" data-testid="ok">
          Email verified.
        </EntryBanner>
        <EntryBanner tone="danger" data-testid="danger">
          The link expired.
        </EntryBanner>
      </>
    )
    expect(screen.getByTestId('info')).toHaveAttribute('role', 'status')
    expect(screen.getByTestId('warn')).toHaveAttribute('role', 'status')
    expect(screen.getByTestId('ok')).toHaveAttribute('role', 'status')
    expect(screen.getByTestId('danger')).toHaveAttribute('role', 'alert')
  })

  it('never forces role="alert" on a notice that is not an error', () => {
    const roots = [join(process.cwd(), 'src'), join(process.cwd(), 'console', 'src')]
    const offenders: string[] = []
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const full = join(dir, name)
        if (statSync(full).isDirectory()) {
          if (name !== '__tests__' && name !== 'node_modules') walk(full)
        } else if (name.endsWith('.tsx') && !name.includes('.test.')) {
          const src = readFileSync(full, 'utf8')
          for (const m of src.matchAll(/<(Alert|EntryBanner)\b([^>]*?)>/gs)) {
            const attrs = m[2]
            if (!/role="alert"/.test(attrs)) continue
            if (/variant="destructive"|tone="danger"/.test(attrs)) continue
            offenders.push(`${full.slice(process.cwd().length + 1)}: <${m[1]}${attrs}>`)
          }
        }
      }
    }
    for (const root of roots) walk(root)
    expect(offenders).toEqual([])
  })
})
