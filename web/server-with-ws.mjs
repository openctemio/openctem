/**
 * Production entry point: Next's standalone server plus same-origin WebSocket.
 *
 * Browsers open the WebSocket on the UI's own origin (ws(s)://<ui-host>/api/v1/ws)
 * so the API port never has to be reachable from them. Next.js route handlers
 * cannot proxy an upgrade, and next.config rewrites are frozen at build time,
 * so this entry forwards that one upgrade itself to BACKEND_API_URL, read when
 * the container starts. Every other request and upgrade goes to Next unchanged.
 *
 * The API authenticates the upgrade with the browser's session cookie and
 * checks its Origin (RFC-045), so the Cookie and Origin headers are forwarded
 * unchanged; this hop adds no trust of its own.
 */
import http from 'node:http'
import net from 'node:net'
import tls from 'node:tls'
import { pathToFileURL } from 'node:url'

const WS_PATH = '/api/v1/ws'

function backendURL() {
  return new URL(process.env.BACKEND_API_URL || 'http://localhost:8080')
}

/** True for the API WebSocket path, with or without a query string. */
export function isApiWebSocket(url) {
  if (typeof url !== 'string') return false
  const q = url.indexOf('?')
  return (q === -1 ? url : url.slice(0, q)) === WS_PATH
}

// The only client headers the API needs for the upgrade. Everything else
// (Forwarded, True-Client-IP, X-Client-IP, custom headers) is dropped, so the
// client cannot hand the API a value this hop did not choose.
const FORWARDED_HEADERS = new Set([
  'upgrade',
  'connection',
  'cookie',
  'origin',
  'user-agent',
  'accept-language',
])

function isForwardedHeader(lowerName) {
  return FORWARDED_HEADERS.has(lowerName) || lowerName.startsWith('sec-websocket-')
}

/** True when the operator declared a header-overwriting reverse proxy (same switch as the HTTP proxy). */
function trustProxyHeaders() {
  return process.env.TRUST_PROXY_HEADERS === 'true'
}

/**
 * Builds the upgrade request sent to the API: same path and query, Host
 * rewritten to the backend, and only the allowlisted client headers above
 * (Cookie and Origin unchanged). The client address is the socket peer as
 * X-Forwarded-For / X-Real-IP, overwritten, never appended. Only when
 * TRUST_PROXY_HEADERS=true, where a gateway in front sets those two headers,
 * the gateway's values are passed on so this path and the HTTP proxy agree.
 */
export function buildUpgradeRequest(req, backend, trusted = trustProxyHeaders()) {
  const lines = [`GET ${req.url} HTTP/1.1`, `Host: ${backend.host}`]
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const name = req.rawHeaders[i]
    if (!isForwardedHeader(name.toLowerCase())) continue
    lines.push(`${name}: ${req.rawHeaders[i + 1]}`)
  }
  const peer = req.socket.remoteAddress || ''
  const header = (n) => {
    const v = req.headers && req.headers[n]
    return typeof v === 'string' ? v.trim() : ''
  }
  const xff = (trusted && header('x-forwarded-for')) || peer
  const realIP = (trusted && header('x-real-ip')) || peer
  if (xff) lines.push(`X-Forwarded-For: ${xff}`)
  if (realIP) lines.push(`X-Real-IP: ${realIP}`)
  lines.push(`X-Forwarded-Proto: ${req.socket.encrypted ? 'https' : 'http'}`)
  if (req.headers.host) lines.push(`X-Forwarded-Host: ${req.headers.host}`)
  return lines.join('\r\n') + '\r\n\r\n'
}

function proxyUpgrade(req, socket, head) {
  const backend = backendURL()
  const secure = backend.protocol === 'https:' || backend.protocol === 'wss:'
  const port = Number(backend.port) || (secure ? 443 : 80)
  const upstream = secure
    ? tls.connect({ host: backend.hostname, port, servername: backend.hostname })
    : net.connect({ host: backend.hostname, port })

  const fail = () => {
    if (socket.writable) socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n')
    upstream.destroy()
  }
  upstream.once('error', fail)
  socket.once('error', () => upstream.destroy())

  upstream.once(secure ? 'secureConnect' : 'connect', () => {
    upstream.removeListener('error', fail)
    upstream.on('error', () => socket.destroy())
    upstream.write(buildUpgradeRequest(req, backend))
    if (head && head.length) upstream.write(head)
    upstream.pipe(socket)
    socket.pipe(upstream)
  })
}

const isEntryPoint = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href

if (isEntryPoint) {
  // Next's standalone server creates its HTTP server with http.createServer;
  // intercept the upgrade event for the API WebSocket path only.
  const createServer = http.createServer
  http.createServer = function patchedCreateServer(...args) {
    const server = createServer.apply(this, args)
    const emit = server.emit
    server.emit = function (event, req, socket, head) {
      if (event === 'upgrade' && isApiWebSocket(req.url)) {
        proxyUpgrade(req, socket, head)
        return true
      }
      return emit.apply(this, arguments)
    }
    return server
  }
  // server.js is Next's standalone output, generated next to this file in the image.
  const nextServer = new URL('./server.js', import.meta.url).href
  await import(/* @vite-ignore */ nextServer)
}
