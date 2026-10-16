/**
 * The product brand of this installation: the name, logos, color and links
 * people see. The API serves it at the public GET /api/v1/brand (server
 * configuration, the same for every organization; api/docs/architecture/brand.md).
 * The web reads it on the server per request (short cache) and hands it to
 * the client through BrandProvider. When the API cannot be reached, or a
 * value is not safe to use, the OpenCTEM defaults apply.
 *
 * This file is the one place in the console that names the default brand.
 */

export interface Brand {
  name: string
  shortName: string
  /** "#rrggbb", or '' to keep the theme color. */
  primaryColor: string
  docsUrl: string
  websiteUrl: string
  supportUrl: string
  supportEmail: string
  termsUrl: string
  privacyUrl: string
  /** Show the "Powered by OpenCTEM" credit (already false for OpenCTEM itself). */
  poweredBy: boolean
  /** Same-origin image paths, or '' for the built-in images. */
  logoLightUrl: string
  logoDarkUrl: string
  faviconUrl: string
}

/** The upstream product, also the name a "Powered by" credit names. */
export const UPSTREAM_NAME = 'OpenCTEM'

export const DEFAULT_BRAND: Brand = {
  name: UPSTREAM_NAME,
  shortName: UPSTREAM_NAME,
  primaryColor: '',
  docsUrl: 'https://docs.openctem.io',
  websiteUrl: 'https://openctem.io',
  supportUrl: '',
  supportEmail: 'info@openctem.io',
  termsUrl: '',
  privacyUrl: '',
  poweredBy: false,
  logoLightUrl: '',
  logoDarkUrl: '',
  faviconUrl: '',
}

/** The API's JSON (snake_case). */
export interface BrandResponse {
  name?: string
  short_name?: string
  primary_color?: string
  docs_url?: string
  website_url?: string
  support_url?: string
  support_email?: string
  terms_url?: string
  privacy_url?: string
  powered_by?: boolean
  logo_light_url?: string
  logo_dark_url?: string
  favicon_url?: string
}

const COLOR = /^#[0-9a-fA-F]{6}$/
const EMAIL = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/
const ASSET_PATH = /^\/api\/v1\/brand\/images\/(logo-light|logo-dark|favicon)(\?v=[0-9a-f]{1,64})?$/
// Markup and placeholder characters never appear in a valid name (the API
// refuses them); a name with them is not used.
const NAME_UNSAFE = /[<>{}`*_~|[\]\\\u0000-\u001f\u007f]/

function str(v: unknown): string {
  return typeof v === 'string' ? v.trim() : ''
}

function name(v: unknown, fallback: string): string {
  const s = str(v)
  return s && s.length <= 64 && !NAME_UNSAFE.test(s) ? s : fallback
}

/** An absolute https URL without credentials, or the fallback. */
export function httpsOnly(v: unknown, fallback = ''): string {
  const s = str(v)
  if (!s) return fallback
  try {
    const u = new URL(s)
    if (u.protocol !== 'https:' || u.username || u.password || !u.hostname) return fallback
    return s
  } catch {
    return fallback
  }
}

function asset(v: unknown): string {
  const s = str(v)
  return ASSET_PATH.test(s) ? s : ''
}

/** Turns the API's answer into a brand, value by value; anything unsafe keeps its default. */
export function toBrand(r: BrandResponse | null | undefined): Brand {
  if (!r || typeof r !== 'object') return DEFAULT_BRAND
  const n = name(r.name, DEFAULT_BRAND.name)
  const light = asset(r.logo_light_url)
  return {
    name: n,
    shortName: name(r.short_name, n),
    primaryColor: COLOR.test(str(r.primary_color)) ? str(r.primary_color) : '',
    docsUrl: httpsOnly(r.docs_url, DEFAULT_BRAND.docsUrl).replace(/\/+$/, ''),
    websiteUrl: httpsOnly(r.website_url, DEFAULT_BRAND.websiteUrl),
    supportUrl: httpsOnly(r.support_url),
    supportEmail: EMAIL.test(str(r.support_email))
      ? str(r.support_email)
      : DEFAULT_BRAND.supportEmail,
    termsUrl: httpsOnly(r.terms_url),
    privacyUrl: httpsOnly(r.privacy_url),
    poweredBy: r.powered_by === true && n !== UPSTREAM_NAME,
    logoLightUrl: light,
    logoDarkUrl: asset(r.logo_dark_url) || light,
    faviconUrl: asset(r.favicon_url),
  }
}

/** A link on the documentation site: `path` is "/sensors/…" or "" for the home page. */
export function docsLink(brand: Pick<Brand, 'docsUrl'>, path = ''): string {
  return `${brand.docsUrl}${path}`
}
