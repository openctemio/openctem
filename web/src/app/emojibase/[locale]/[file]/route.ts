/**
 * Self-hosted Emojibase data for the reaction emoji picker (frimousse).
 *
 * The picker would otherwise fetch it from cdn.jsdelivr.net, which the
 * production CSP (`connect-src 'self' …`) blocks and which would tell a third
 * party who opens a picker. Built once at build time (force-static) from the
 * pinned `emojibase-data` package; only the English files are served.
 */

import data from 'emojibase-data/en/data.json'
import messages from 'emojibase-data/en/messages.json'

export const dynamic = 'force-static'
// Only the generated paths exist; anything else is a 404 without running GET.
export const dynamicParams = false

const FILES: Record<string, unknown> = {
  'data.json': data,
  'messages.json': messages,
}

export function generateStaticParams() {
  return Object.keys(FILES).map((file) => ({ locale: 'en', file }))
}

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ locale: string; file: string }> }
) {
  const { locale, file } = await ctx.params
  const body = locale === 'en' ? FILES[file] : undefined
  if (body === undefined) {
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } })
  }
  return new Response(JSON.stringify(body), {
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'public, max-age=86400',
    },
  })
}
