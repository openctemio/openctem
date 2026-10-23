import { describe, it, expect } from 'vitest'
import { buildFindingsQuery } from '@/features/findings/api/use-findings-api'
import type { FindingApiFilters } from '@/features/findings/api/finding-api.types'
import { FINDINGS_LIST_HIDDEN_STATUSES } from '../list-defaults'
import { MY_WORK_METRIC_FILTERS, findingsDrillUrl, type MyWorkMetricKey } from '../my-work-metrics'

/** What the Findings page turns a URL into (its apiFilters), for the params My work links use. */
function parseLikeFindingsPage(url: string): FindingApiFilters {
  const p = new URL(url, 'http://x').searchParams
  const list = (k: string) => (p.get(k) ? p.get(k)!.split(',') : undefined)
  const f: FindingApiFilters = {}
  if (p.get('related_to') === 'me') f.assigned_to_me = true
  if (list('severity')) f.severities = list('severity') as FindingApiFilters['severities']
  if (list('sla_status')) f.sla_statuses = list('sla_status') as FindingApiFilters['sla_statuses']
  f.state = (p.get('state') as FindingApiFilters['state']) ?? 'open'
  // No status filter in the URL: the list hides its pentest work in progress.
  if (!p.get('status')) f.exclude_statuses = [...FINDINGS_LIST_HIDDEN_STATUSES]
  return f
}

const strip = (f: FindingApiFilters) => ({
  ...f,
  page: undefined,
  per_page: undefined,
  sort: undefined,
})

describe('My work drill links', () => {
  const keys = Object.keys(MY_WORK_METRIC_FILTERS) as MyWorkMetricKey[]

  it.each(keys)('%s: the count filter equals the filter its drill link opens', (key) => {
    const counted = MY_WORK_METRIC_FILTERS[key]
    const opened = parseLikeFindingsPage(findingsDrillUrl(counted))
    expect(buildFindingsQuery(strip(opened)).toString()).toBe(
      buildFindingsQuery(strip(counted)).toString()
    )
  })

  it('opens the same severities and SLA statuses the figures count', () => {
    expect(findingsDrillUrl(MY_WORK_METRIC_FILTERS.critical)).toContain('severity=critical%2Chigh')
    expect(findingsDrillUrl(MY_WORK_METRIC_FILTERS.critical)).not.toContain('priority_class')
    expect(findingsDrillUrl(MY_WORK_METRIC_FILTERS.overdue)).toContain(
      'sla_status=overdue%2Cexceeded'
    )
  })

  it('counts with the Open lens and without the list-hidden statuses', () => {
    for (const k of keys) {
      expect(MY_WORK_METRIC_FILTERS[k].state).toBe('open')
      expect(MY_WORK_METRIC_FILTERS[k].exclude_statuses).toEqual([...FINDINGS_LIST_HIDDEN_STATUSES])
      expect(findingsDrillUrl(MY_WORK_METRIC_FILTERS[k])).toContain('state=open')
    }
  })
})
