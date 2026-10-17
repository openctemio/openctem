/**
 * GET /api/version: the web app's build (Help > About).
 *
 * Signed-in users only (the same session-cookie check the proxy uses for
 * pages), like the API's /api/v1/version: an
 * anonymous client does not get the commit of a development deployment.
 */
import { NextResponse, type NextRequest } from 'next/server'

import { isAuthenticated } from '@/lib/middleware/auth'
import { resolveWebBuildInfo } from '@/lib/version/web-build-info'

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  if (!isAuthenticated(request)) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }
  const info = await resolveWebBuildInfo()
  return NextResponse.json(info, { headers: { 'Cache-Control': 'no-store' } })
}
