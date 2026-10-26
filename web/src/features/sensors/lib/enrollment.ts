/**
 * Pure helpers of the enrollment token form (api
 * docs/architecture/sensor-pairing.md, "Enrollment tokens"). The API checks
 * every bound again; these only let the form say what is wrong before it
 * sends.
 */

export const TOKEN_TTL_OPTIONS = [1, 24, 24 * 7, 24 * 30] as const
export const DEFAULT_TOKEN_TTL_HOURS = 24
export const DEFAULT_TOKEN_USES = 10
export const MAX_TOKEN_USES = 1000
export const MAX_TOKEN_LABELS = 20
export const MAX_TOKEN_CIDRS = 20

const LABEL_KEY = /^[a-z0-9][a-z0-9._/-]{0,62}$/
const IPV4_CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/
const IPV6_CIDR = /^[0-9a-fA-F:]+\/(\d{1,3})$/

/** "env=prod" lines into a map; null when a line is not key=value or a key is not allowed. */
export function parseLabels(text: string): Record<string, string> | null {
  const out: Record<string, string> = {}
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line) continue
    const eq = line.indexOf('=')
    if (eq <= 0) return null
    const key = line.slice(0, eq).trim()
    const value = line.slice(eq + 1).trim()
    if (!LABEL_KEY.test(key) || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value))
      return null
    out[key] = value
  }
  return Object.keys(out).length > MAX_TOKEN_LABELS ? null : out
}

function validCidr(c: string): boolean {
  const m = IPV4_CIDR.exec(c)
  if (m) return m.slice(1, 5).every((o) => Number(o) <= 255) && Number(m[5]) <= 32
  const m6 = IPV6_CIDR.exec(c)
  return !!m6 && c.includes(':') && Number(m6[1]) <= 128
}

/** One CIDR per line (or comma-separated); null when one is not a CIDR. */
export function parseCidrs(text: string): string[] | null {
  const out = text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean)
  if (out.length > MAX_TOKEN_CIDRS || !out.every(validCidr)) return null
  return out
}

export function validUses(n: number): boolean {
  return Number.isInteger(n) && n >= 1 && n <= MAX_TOKEN_USES
}

/** The env line a released sensor reads the token from (a file keeps it out of the environment). */
export const TOKEN_FILE_ENV = 'SENSOR_ENROLLMENT_TOKEN_FILE'

/**
 * How to hand the token to a sensor: pasted into a root-only file (so it is
 * in no shell history and no process list) that the install mounts
 * read-only. The token itself is never part of the snippet.
 */
export const TOKEN_SETUP_SNIPPET = [
  '# Paste the token, then press Ctrl-D: it goes into a root-only file,',
  '# never into the shell history or the command line.',
  'sudo install -d -m 0755 /etc/openctem',
  "sudo sh -c 'umask 077; cat > /etc/openctem/enrollment-token'",
  '# Readable by the sensor only: the container image runs as uid 999',
  '# (a Linux service: chown openctem:openctem).',
  'sudo chown 999:999 /etc/openctem/enrollment-token',
  '',
  '# Add to the install command from Add sensor (/etc/openctem is mounted',
  '# read-only into the container):',
  `#   -e ${TOKEN_FILE_ENV}=/etc/openctem/enrollment-token`,
  '# (needs a sensor release that reads SENSOR_ENROLLMENT_TOKEN_FILE)',
  '# Kubernetes: keep it in a Secret and mount it as a file:',
  '#   kubectl create secret generic openctem-enrollment --from-file=token=/etc/openctem/enrollment-token',
].join('\n')
