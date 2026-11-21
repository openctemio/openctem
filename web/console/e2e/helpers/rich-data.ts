import type { Page } from '@playwright/test'
import type { Scenario } from '../../../e2e/helpers/text-breaks'

/**
 * List answers that are hard on a console page's layout, for the layout-break
 * check of pages.spec.ts: 200 rows (or 0, or 1) with long and Vietnamese
 * addresses and names, every state the page shows, optional fields present on
 * some rows and absent on others. Made-up people on example.* domains.
 */

const LONG_EMAIL =
  'nguyen-thi-phuong-thao-phong-an-ninh-thong-tin-chi-nhanh-17@subsidiary.department.example.com.vn'
const LONG_VI_NAME =
  'Nguyễn Thị Phương Thảo Trưởng Phòng Kiểm Soát Rủi Ro An Ninh Thông Tin Khu Vực Miền Nam'
const PROVIDERS = ['local', 'oidc', 'saml', 'google', 'microsoft', 'github', 'local', 'gitlab']
const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString()
const id = (n: number) => `01a1f770-0000-7000-8000-${String(n).padStart(12, '0')}`

function rowCount(scen: Scenario) {
  return scen === 'empty' ? 0 : scen === 'one' ? 1 : 200
}

function platformUser(i: number) {
  return {
    id: id(i),
    email:
      i % 7 === 0
        ? LONG_EMAIL.replace('17@', `${i}@`)
        : `nguoidung${String(i).padStart(3, '0')}@example.com.vn`,
    status: i % 31 === 5 ? 'suspended' : i % 37 === 6 ? 'inactive' : 'active',
    auth_provider: PROVIDERS[i % PROVIDERS.length],
    email_verified: i % 5 !== 0,
    locked: i % 9 === 0,
    blocked: i % 11 === 0,
    last_login_at: i % 4 === 0 ? undefined : ago(i * 53),
    created_at: ago(i * 4000 + 30),
    memberships: [0, 1, 3, 128][i % 4],
    mfa_enabled: i % 3 === 0,
    is_platform_admin: i % 13 === 1,
    erased: i % 29 === 3,
  }
}

function adminSession(i: number) {
  const roles = ['super_admin', 'ops_admin', 'readonly'] as const
  return {
    id: id(i),
    admin_id: id(1000 + (i % 40)),
    admin_email: i % 5 === 1 ? LONG_EMAIL : `quantri${String(i).padStart(3, '0')}@example.org`,
    admin_name: i % 5 === 1 ? LONG_VI_NAME : i % 3 === 0 ? '' : `Trần Văn Đức ${i}`,
    admin_role: roles[i % 3],
    break_glass: i % 17 === 2,
    auth_method: i % 2 ? 'password' : 'idp',
    mfa_verified: true,
    ip_address:
      i % 6 === 3
        ? undefined
        : i % 2
          ? `198.51.100.${i % 250}`
          : '2001:db8:85a3:8d3:1319:8a2e:370:7348',
    user_agent: 'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
    created_at: ago(i * 37 + 5),
    last_seen_at: ago(i % 4 === 0 ? 0.3 : i * 3),
    expires_at: new Date(Date.now() + 8 * 3600_000).toISOString(),
    current: i === 0,
  }
}

/** Answers per console route: the list request and its body for a scenario. */
export const CONSOLE_LIST_DATA: Record<string, { url: string; body: (s: Scenario) => unknown }> = {
  '/users': {
    url: '**/api/v1/admin/platform-users?*',
    body: (scen) => {
      const n = rowCount(scen)
      const data = Array.from({ length: Math.min(n, 25) }, (_, i) => platformUser(i))
      return {
        data,
        total: n,
        page: 1,
        per_page: 25,
        total_pages: Math.max(1, Math.ceil(n / 25)),
        counts: n
          ? {
              all: n,
              active: 171,
              unverified: 40,
              locked: 23,
              blocked: 19,
              mfa_off: 134,
              platform_admins: 16,
            }
          : { all: 0 },
      }
    },
  },
  '/security/sessions': {
    url: '**/api/v1/admin/console-sessions',
    body: (scen) => ({ data: Array.from({ length: rowCount(scen) }, (_, i) => adminSession(i)) }),
  },
}

/** Serves the route's list answer from CONSOLE_LIST_DATA for GET requests. */
export async function consoleListData(page: Page, route: string, scen: Scenario) {
  const d = CONSOLE_LIST_DATA[route]
  if (!d) return
  await page.route(d.url, (r) =>
    r.request().method() === 'GET' ? r.fulfill({ json: d.body(scen) }) : r.fallback()
  )
}
