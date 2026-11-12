/**
 * Browser storage outlives a switch of organization. Every file that touches
 * localStorage or sessionStorage is listed here with the reason its values
 * cannot show one organization's data in another: the key carries the
 * organization (or a record id that exists in one organization only), the
 * value is dropped by clearOrgScopedClientState on every switch, or the value
 * is not organization data (a UI preference, the account, the session).
 * A new file fails this test until it is classified
 * (web/docs/organization-switch.md).
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import {
  ORG_SCOPED_LOCAL_KEYS,
  ORG_SCOPED_SESSION_KEYS,
  clearOrgScopedClientState,
} from '@/lib/org-scoped-storage'

type Reason = 'org-keyed' | 'cleared-on-switch' | 'not-org-data'

const CLASSIFIED: Record<string, Reason> = {
  // Keyed by organization id (or by a record id of one organization).
  'src/features/activity/lib/activity-storage.ts': 'org-keyed',
  'src/features/assets/hooks/use-last-visit.ts': 'org-keyed',
  'src/features/attack-surface/components/easm-decide-panel.tsx': 'org-keyed',
  'src/features/organization/hooks/use-tenant-logo.ts': 'org-keyed',
  'src/features/scans/hooks/use-new-scan-draft.ts': 'org-keyed',
  'src/lib/logo-storage.ts': 'org-keyed',
  'src/lib/permission-storage.ts': 'org-keyed',
  // Addresses only, each with the organization it was shown in.
  'src/lib/tenant-epoch.ts': 'org-keyed',
  // Dropped on every switch (clearOrgScopedClientState).
  'src/app/(dashboard)/dashboards/page.tsx': 'cleared-on-switch',
  'src/components/layout/settings-sidebar-nav.tsx': 'cleared-on-switch',
  'src/features/dashboards/components/dashboard-home.tsx': 'cleared-on-switch',
  'src/features/dashboards/landing.ts': 'cleared-on-switch',
  'src/features/findings/hooks/use-triage-session.ts': 'cleared-on-switch',
  'src/features/findings/lib/list-context.ts': 'cleared-on-switch',
  'src/features/findings/lib/triage-session.ts': 'cleared-on-switch',
  'src/features/pentest/hooks/use-local-draft.ts': 'cleared-on-switch',
  'src/features/query/lib/recent.ts': 'cleared-on-switch',
  'src/lib/form-drafts.ts': 'cleared-on-switch',
  'src/lib/org-scoped-storage.ts': 'cleared-on-switch',
  // UI preferences, the account, the session: no organization data.
  'src/app/(dashboard)/(validation)/pentest/campaigns/page.tsx': 'not-org-data',
  'src/components/dashboard-kit/source-view.tsx': 'not-org-data',
  'src/components/layout/shell-banner-slot.tsx': 'not-org-data',
  'src/components/layout/tenant-gate.tsx': 'not-org-data',
  'src/components/sign-out-dialog.tsx': 'not-org-data',
  'src/components/ui/image-upload.tsx': 'not-org-data',
  'src/features/account/api/use-preferences.ts': 'not-org-data',
  'src/features/account/components/account-sign-out.tsx': 'not-org-data',
  'src/features/account/components/welcome-hub.tsx': 'not-org-data',
  'src/features/activity/lib/reactions.ts': 'not-org-data',
  'src/features/announcements/components/platform-announcement-banner.tsx': 'not-org-data',
  'src/features/auth/components/login-form.tsx': 'not-org-data',
  'src/features/auth/lib/invitation-token.ts': 'not-org-data',
  'src/features/components/components/components-list-view.tsx': 'not-org-data',
  'src/features/dashboards/layout-hint.ts': 'not-org-data',
  'src/features/remediation-hub/components/task-detail.tsx': 'not-org-data',
  'src/features/sensors/components/tool-settings-list.tsx': 'not-org-data',
  'src/features/shared/components/data-table/use-table-density.ts': 'not-org-data',
  'src/features/shared/components/filter-panel-layout.tsx': 'not-org-data',
  'src/features/vulnerabilities/components/vulnerability-filters.tsx': 'not-org-data',
  'src/hooks/use-display-user.ts': 'not-org-data',
  'src/lib/auth-refresh-lock.ts': 'not-org-data',
  'src/lib/deployment-skew.ts': 'not-org-data',
  'src/test/setup.ts': 'not-org-data',
}

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      if (name === '__tests__') continue
      sources(full, out)
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name)) {
      out.push(full)
    }
  }
  return out
}

describe('browser storage and the organization switch', () => {
  it('every file using browser storage is classified', () => {
    const using = sources(join(process.cwd(), 'src'))
      .filter((f) => /\b(localStorage|sessionStorage)\b/.test(readFileSync(f, 'utf8')))
      .map((f) => relative(process.cwd(), f).split('\\').join('/'))
      .sort()
    const unclassified = using.filter((f) => !(f in CLASSIFIED))
    expect(unclassified).toEqual([])
    // Entries for files that no longer use storage are removed too.
    expect(Object.keys(CLASSIFIED).filter((f) => !using.includes(f))).toEqual([])
  })

  it('the keys of the cleared files are the ones the switch drops', () => {
    const src = (p: string) => readFileSync(join(process.cwd(), p), 'utf8')
    expect(src('src/features/findings/lib/triage-session.ts')).toContain(
      `'${ORG_SCOPED_SESSION_KEYS[0]}'`
    )
    expect(src('src/features/findings/lib/list-context.ts')).toContain(
      `'${ORG_SCOPED_SESSION_KEYS[1]}'`
    )
    expect(src('src/components/layout/settings-sidebar-nav.tsx')).toContain(
      `'${ORG_SCOPED_SESSION_KEYS[2]}'`
    )
    expect(src('src/features/dashboards/landing.ts')).toContain(`'${ORG_SCOPED_LOCAL_KEYS[0]}'`)
  })
})

describe('clearOrgScopedClientState', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
  })

  it("drops the previous organization's ids, addresses and choices", () => {
    sessionStorage.setItem('openctem.findings.triage', '{"ids":["f-a-1"]}')
    sessionStorage.setItem('openctem.findings.listContext', '{"ids":["f-a-1"]}')
    sessionStorage.setItem('openctem:settings-return-to', '/findings?page=5')
    localStorage.setItem('openctem:dashboard-choice', 'custom:dash-a')
    localStorage.setItem('pentest-finding-draft', '{"title":"A"}')
    localStorage.setItem('openctem:table-density', 'compact')

    clearOrgScopedClientState('org-a')

    for (const k of ORG_SCOPED_SESSION_KEYS) expect(sessionStorage.getItem(k)).toBeNull()
    for (const k of ORG_SCOPED_LOCAL_KEYS) expect(localStorage.getItem(k)).toBeNull()
    expect(localStorage.getItem('pentest-finding-draft')).toBeNull()
    // A UI preference is not organization data: it stays.
    expect(localStorage.getItem('openctem:table-density')).toBe('compact')
  })
})
