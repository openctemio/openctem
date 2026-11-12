import { createServer, type Server } from 'node:http'

import { FIXTURE_SETS, routeTable, type FixtureSet } from './fixtures/api'

/**
 * The backend of the web server while the design gate runs: it answers from
 * the fixture module only (never a real API, never live data) and listens on
 * 127.0.0.1. Tests pick the fixture set and read the unmocked requests over
 * two control routes, which exist only on this mock:
 *
 *   POST /__design/fixture?set=<sample|long|empty>   switch the set, clear the log
 *   GET  /__design/misses                            requests no fixture answered
 */

export interface MockApi {
  server: Server
  url: string
}

export function startMockApi(port: number): Promise<MockApi> {
  let set: FixtureSet = 'sample'
  let misses: string[] = []

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
      res.end(JSON.stringify(body))
    }

    if (url.pathname === '/__design/fixture' && req.method === 'POST') {
      const next = url.searchParams.get('set') as FixtureSet
      if (!FIXTURE_SETS.includes(next)) return json(400, { error: 'unknown fixture set' })
      set = next
      misses = []
      return json(200, { set })
    }
    if (url.pathname === '/__design/misses') return json(200, { set, misses })

    const key = `${req.method} ${url.pathname}`
    const answer = routeTable(set)[key]
    if (!answer) {
      if (!misses.includes(key)) misses.push(key)
      return json(404, { success: false, error: { code: 'NOT_MOCKED', message: key } })
    }
    return json(answer.status ?? 200, answer.body)
  })

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${port}` }))
  })
}
