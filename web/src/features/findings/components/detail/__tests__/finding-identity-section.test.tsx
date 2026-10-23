import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import en from '@/lib/i18n/dictionaries/en/findings.json'
import vi from '@/lib/i18n/dictionaries/vi/findings.json'
import type { FindingIdentity } from '../../../api/use-finding-identity'
import { FindingIdentityView } from '../finding-identity-section'

function identity(over: Partial<FindingIdentity> = {}): FindingIdentity {
  return {
    algo: 'v2/sca',
    version: 2,
    fields: ['asset', 'component', 'vuln'],
    derived: false,
    legacy: false,
    sources: [{ tool: 'trivy', last_seen_at: '2026-10-20T00:00:00Z' }, { tool: 'grype' }],
    merged: [],
    ...over,
  }
}

describe('FindingIdentityView', () => {
  it('states the recipe in plain words and lists the reporting tools', () => {
    render(<FindingIdentityView identity={identity()} />)
    expect(
      screen.getByText(
        'Findings are one when they share: asset, package without version, vulnerability'
      )
    ).toBeInTheDocument()
    expect(screen.getByText('Package vulnerability')).toBeInTheDocument()
    const tools = screen.getByRole('list', { name: 'Reported by' })
    expect(within(tools).getByText('trivy')).toBeInTheDocument()
    expect(within(tools).getByText('grype')).toBeInTheDocument()
    expect(screen.getByText('No other finding was merged into this one')).toBeInTheDocument()
  })

  it('links each merged duplicate to its finding with the cause', () => {
    render(
      <FindingIdentityView
        identity={identity({
          merged: [
            {
              id: '01a16640-b483-7617-aa1c-06f28e1c0113',
              tool_name: 'grype',
              merged_at: '2026-10-21T10:00:00Z',
              reason: 'asset_merge',
            },
            {
              id: '01a16640-b48a-72ae-b764-b186adc103b2',
              tool_name: '',
              merged_at: '2026-10-20T10:00:00Z',
              reason: '',
            },
          ],
        })}
      />
    )
    const list = screen.getByRole('list', { name: 'Merged duplicates' })
    const links = within(list).getAllByRole('link')
    expect(links).toHaveLength(2)
    expect(links[0]).toHaveAttribute('href', '/findings/01a16640-b483-7617-aa1c-06f28e1c0113')
    expect(list).toHaveTextContent('assets merged')
    expect(list).toHaveTextContent('merged')
  })

  it('explains a legacy version-1 key without a recipe', () => {
    render(
      <FindingIdentityView
        identity={identity({ algo: '', version: 1, fields: [], legacy: true, sources: [] })}
      />
    )
    expect(screen.getByText(/keyed by an earlier recipe that was not recorded/)).toBeInTheDocument()
    expect(screen.getByText('No tool recorded')).toBeInTheDocument()
    expect(screen.queryByText('Package vulnerability')).not.toBeInTheDocument()
  })

  it('explains the earlier scanner key and the manual key', () => {
    const { unmount } = render(
      <FindingIdentityView identity={identity({ algo: 'v1/ingest', version: 1, fields: [] })} />
    )
    expect(screen.getByText(/earlier scanner key matches/)).toBeInTheDocument()
    unmount()
    render(
      <FindingIdentityView
        identity={identity({
          algo: 'manual/v1',
          version: 1,
          fields: ['asset', 'rule', 'path', 'line', 'message'],
        })}
      />
    )
    expect(
      screen.getByText('Findings are one when they share: asset, rule, file path, line, message')
    ).toBeInTheDocument()
    expect(screen.getByText('Manual finding key')).toBeInTheDocument()
  })
})

describe('identity explanation i18n', () => {
  it('has every key it uses in English and Vietnamese', () => {
    const src = readFileSync(join(__dirname, '..', 'finding-identity-section.tsx'), 'utf8')
    const used = [...src.matchAll(/t\(\s*'([^']+)'/g)].map((m) => m[1])
    expect(used.length).toBeGreaterThan(40)
    const enKeys = en as Record<string, string>
    const viKeys = vi as Record<string, string>
    for (const k of used) {
      expect(enKeys[k], `en ${k}`).toBeTruthy()
      expect(viKeys[k], `vi ${k}`).toBeTruthy()
    }
    // Vietnamese is translated, not copied.
    expect(viKeys['findings.identity.heading']).not.toBe(enKeys['findings.identity.heading'])
  })
})
