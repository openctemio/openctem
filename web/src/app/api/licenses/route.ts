/**
 * GET /api/licenses: the web app's third-party notices (About > Open-source
 * licenses). Signed-in users only (the same session-cookie check as
 * /api/version), so anonymous clients do not get the exact dependency
 * versions. No tenant data; the file is fixed (src/lib/notices).
 */
import { NextResponse, type NextRequest } from 'next/server'

import { isAuthenticated } from '@/lib/middleware/auth'
import { readWebNotices } from '@/lib/notices/read-web-notices'

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  if (!isAuthenticated(request)) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }
  return NextResponse.json(await readWebNotices(), {
    headers: { 'Cache-Control': 'private, max-age=3600' },
  })
}
