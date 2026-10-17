/** Health check of the console service (container health checks, load balancers). */
import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

export function GET() {
  return NextResponse.json({ status: 'ok', service: 'console' }, { status: 200 })
}
