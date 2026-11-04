import { createHmac } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Decode(input: string): Buffer {
  let bits = ''
  for (const c of input.replace(/[\s=-]/g, '').toUpperCase()) {
    const v = ALPHABET.indexOf(c)
    if (v < 0) throw new Error('not a base32 secret')
    bits += v.toString(2).padStart(5, '0')
  }
  const bytes: number[] = []
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(bytes)
}

/** RFC 6238 code (SHA-1, 6 digits, 30 s) of a base32 secret, for the given 30 s step. */
export function totp(secret: string, step = Math.floor(Date.now() / 30_000)): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const h = createHmac('sha1', base32Decode(secret)).update(counter).digest()
  const o = h[h.length - 1] & 0xf
  const n = (h.readUInt32BE(o) & 0x7fffffff) % 1_000_000
  return String(n).padStart(6, '0')
}

const LAST_STEP = path.resolve(process.cwd(), '.console-e2e-auth/last-totp-step')

/**
 * A code the API has not accepted yet. The API refuses a code twice (it keeps
 * the last accepted 30 s step), and the sign-in, the elevations and the specs
 * run in different processes, so the last step used is kept in a file; this
 * waits for the next step when the current one was already used.
 */
export async function freshTotp(secret: string): Promise<string> {
  let last = -1
  try {
    last = Number(fs.readFileSync(LAST_STEP, 'utf8'))
  } catch {
    // none used yet
  }
  let step = Math.floor(Date.now() / 30_000)
  if (step <= last) {
    await new Promise((r) => setTimeout(r, (last + 1) * 30_000 - Date.now() + 500))
    step = Math.floor(Date.now() / 30_000)
  }
  fs.mkdirSync(path.dirname(LAST_STEP), { recursive: true })
  fs.writeFileSync(LAST_STEP, String(step))
  return totp(secret, step)
}
