/**
 * GET /api/v1/admin/web-licenses: the console build's third-party notices
 * (About > Open-source licenses). Served by the console itself (the API has
 * its own at /api/v1/admin/licenses); this static route takes precedence over
 * the admin API proxy. Only a browser holding a console session cookie gets
 * them (the cookie is scoped to /api/v1/admin, so it reaches this route), so
 * anonymous clients do not get the exact dependency versions. No tenant data;
 * the file is fixed (src/lib/notices).
 */
import { NextResponse, type NextRequest } from 'next/server'

import { readWebNotices } from '@/lib/notices/read-web-notices'

export const dynamic = 'force-dynamic'

const SESSION_COOKIE = 'admin_session'

export async function GET(request: NextRequest) {
  if (!request.cookies.get(SESSION_COOKIE)?.value) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }
  return NextResponse.json(await readWebNotices(), {
    headers: { 'Cache-Control': 'private, no-store' },
  })
}
