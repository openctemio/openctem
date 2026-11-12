import { LONG, ORGANIZATION } from './sample-data'

/**
 * The API answers of the design gate, by fixture set and route. The mock API
 * (mock-api.ts) is the web server's backend while the gate runs, so the same
 * answers reach server-rendered reads and the browser's /api/v1 calls; a route
 * that is not listed here answers 404 and is reported as unmocked, which fails
 * a page in the manifest.
 *
 *   sample  the design's dataset (sample-data.ts), what the boards show
 *   long    the longest values (long names, large counts) for the layout pass
 *   empty   nothing configured or listed yet
 *
 * Server-rendered reads (brand, legal) are cached by the web server for a
 * minute, so their answers are the same in every set: vary only data the
 * browser fetches.
 */

export type FixtureSet = 'sample' | 'long' | 'empty'

export const FIXTURE_SETS: readonly FixtureSet[] = ['sample', 'long', 'empty']

export interface MockAnswer {
  status?: number
  body: unknown
}

/** Key: `METHOD /path`, without the query string. */
export type RouteTable = Record<string, MockAnswer>

const SERVER_RENDERED: RouteTable = {
  'GET /api/v1/brand': { body: {} },
  'GET /api/v1/legal': {
    body: {
      terms_url: 'https://example.com/terms',
      privacy_url: 'https://example.com/privacy',
      pages_enabled: false,
    },
  },
}

const PASSWORD_POLICY = { min_length: 12, require_mixed_case: true, require_number: true }

function providers(set: FixtureSet): MockAnswer {
  const on = set !== 'empty'
  return {
    body: {
      social: { google: on, github: on, microsoft: on },
      sso_env_entra_enabled: on,
      registration_enabled: on,
      tenant_creation_mode: on ? 'self_service' : 'admin_only',
      request_access: false,
      password_policy: PASSWORD_POLICY,
      email_delivery: true,
    },
  }
}

function ssoProviders(set: FixtureSet): MockAnswer {
  if (set === 'empty') return { body: { providers: [] } }
  const name = set === 'long' ? LONG.providerName : `${ORGANIZATION.name} sign-in`
  return {
    body: {
      providers: [
        { id: '00000000-0000-4000-8000-000000000001', provider: 'entra_id', display_name: name },
        { id: '00000000-0000-4000-8000-000000000002', provider: 'okta', display_name: name },
      ],
    },
  }
}

export function routeTable(set: FixtureSet): RouteTable {
  return {
    ...SERVER_RENDERED,
    'GET /api/v1/auth/providers': providers(set),
    'GET /api/v1/auth/sso/providers': ssoProviders(set),
  }
}
