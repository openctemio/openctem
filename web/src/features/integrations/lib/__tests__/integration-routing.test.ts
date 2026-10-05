import { describe, it, expect } from 'vitest'
import {
  integrationManageHref,
  notificationChannelsOnly,
  siemIntegrationsOnly,
} from '../integration-routing'

const slack = { provider: 'slack', category: 'notification' } as const
const splunk = { provider: 'splunk', category: 'notification' } as const
const jira = { provider: 'jira', category: 'ticketing' } as const

describe('integration routing', () => {
  it('Splunk is not listed (or editable) as a notification channel', () => {
    expect(notificationChannelsOnly([slack, splunk])).toEqual([slack])
    expect(siemIntegrationsOnly([slack, splunk])).toEqual([splunk])
  })

  it('Manage for Splunk goes to the SIEM page, not Notification channels', () => {
    expect(integrationManageHref(splunk)).toBe('/settings/integrations/siem')
    expect(integrationManageHref(slack)).toBe('/settings/integrations/notifications')
    expect(integrationManageHref(jira)).toBe('/settings/integrations/ticketing')
  })
})
