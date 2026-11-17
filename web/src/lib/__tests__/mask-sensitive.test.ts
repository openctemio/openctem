import { describe, expect, it } from 'vitest'

import { EMAIL_MASK, SECRET_MASK, hasSecretMask, maskSensitiveText } from '../mask-sensitive'

const M = SECRET_MASK

// Obviously fake values, assembled so no scanner takes this file for a leak.
const AWS = 'AKIAIOSFODNN7EXAMPLE'
const GH = `ghp_${'0123456789abcdefghijABCDEFGHIJ012345'}`
const GH_PAT = `github_pat_${'11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789'}`
const SLACK = `xoxb-${'123456789012-123456789012-abcdefghijklmnopqrstuvwx'}`
const STRIPE = `sk_live_${'abcdefghijklmnopqrstuvwx0123'}`
const STRIPE_R = `rk_live_${'abcdefghijklmnopqrstuvwx0123'}`
const JWT = `eyJhbGciOiJIUzI1NiJ9.${'eyJzdWIiOiJleGFtcGxlIn0'}.${'c2lnbmF0dXJlLWV4YW1wbGU'}`
const GENERIC = 'Zx9Qw3Er7Ty1Ui5Op2As4Df6Gh8Jk0LzXc'

describe('maskSensitiveText', () => {
  const masked: [string, string, string][] = [
    [
      'an e-mail address',
      'Leak of admin@example.com in logs',
      `Leak of ${EMAIL_MASK}@example.com in logs`,
    ],
    [
      'a URL-encoded address',
      '/reset?u=jane.doe%40example.com',
      `/reset?u=${EMAIL_MASK}%40example.com`,
    ],
    ['two addresses', 'a@example.com,b.c@mail.example.org', '***@example.com,***@mail.example.org'],
    [
      'URL credentials',
      'clone https://ci:s3cr3t@git.example.com/a.git',
      `clone https://${M}@git.example.com/a.git`,
    ],
    [
      'URL credentials, other scheme',
      'postgres://app:pw@db.example.com:5432/x',
      `postgres://${M}@db.example.com:5432/x`,
    ],
    ['an AWS access key id', `Key ${AWS} in config.yml`, `Key AKIA${M}MPLE in config.yml`],
    ['a temporary AWS key id', 'ASIAIOSFODNN7EXAMPLE', `ASIA${M}MPLE`],
    ['a GitHub token', `token ${GH} found`, `token ghp_${M}2345 found`],
    ['a fine-grained GitHub token', GH_PAT, `gith${M}6789`],
    ['a Slack token', `${SLACK}.`, `xoxb${M}uvwx.`],
    ['a Stripe live key', STRIPE, `sk_l${M}0123`],
    ['a Stripe restricted key', STRIPE_R, `rk_l${M}0123`],
    ['a JWT', `jwt ${JWT} end`, `jwt eyJh${M}wbGU end`],
    [
      'a Bearer token',
      'curl -H "Authorization: Bearer abcDEF123456ghi"',
      `curl -H "Authorization: Bearer abc${M}ghi"`,
    ],
    ['a bare Bearer token', 'Bearer abcdef0123456789', `Bearer abcd${M}6789`],
    ['password=', 'login?user=x&password=hunter2hunter2!!', `login?user=x&password=hunt${M}r2!!`],
    ['a short password', 'password=hunter2', `password=h${M}2`],
    ['a tiny value', 'pwd=abcd', `pwd=a${M}d`],
    ['secret=', 'secret=topsecretvalue99', `secret=tops${M}ue99`],
    ['token=', 'csrf_token=abcdefgh12345678', `csrf_token=abcd${M}5678`],
    ['api_key=', 'api_key=abcdefgh12345678', `api_key=abcd${M}5678`],
    ['a JSON member', '{"password": "summer"}', `{"password": "s${M}r"}`],
    [
      'key: value with a non-word',
      'Hardcoded password: hunter2 in app.yml',
      `Hardcoded password: h${M}2 in app.yml`,
    ],
    ['a long mixed token', `value ${GENERIC} here`, `value Zx9Q${M}LzXc here`],
    [
      'a private key block',
      'key -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAexample\n-----END RSA PRIVATE KEY----- end',
      `key -----BEGIN RSA PRIVATE KEY-----${M} end`,
    ],
    [
      'a private key with no footer',
      '-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC found',
      `-----BEGIN PRIVATE KEY-----${M} found`,
    ],
  ]
  it.each(masked)('masks %s', (_name, input, want) => {
    expect(maskSensitiveText(input)).toBe(want)
  })

  it('never leaves the value of any kind in the output', () => {
    const secrets = [AWS, GH, GH_PAT, SLACK, STRIPE, STRIPE_R, JWT, GENERIC, 'admin@example.com']
    const out = maskSensitiveText(`Found ${secrets.join(' and ')} in src/app.ts`)
    for (const s of secrets) expect(out).not.toContain(s)
    // The other words stay.
    expect(out.startsWith('Found ')).toBe(true)
    expect(out.endsWith(' in src/app.ts')).toBe(true)
    expect(out.split(' and ')).toHaveLength(secrets.length)
  })

  const kept = [
    'CVE-2024-12345 in nginx 1.15.5',
    'CWE-79: Cross-site scripting',
    'GHSA-jfh8-c2jp-5v3q in lodash@4.17.20',
    '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
    'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    'image registry.example.com/app@sha256:abcdef0123456789',
    'lib@1.2.3 and @scope/pkg@4.5.6',
    'Weak password: reuse allowed',
    'Secret: detected in repository',
    'Missing Bearer authentication on /api/v1/users',
    'Authorization: required for every route',
    'Private key header -----BEGIN PRIVATE KEY----- detected',
    'https://shop.example.com/api/v2/orders?id=1&sort=asc',
    'src/main/java/com/example/OAuthAuthorizationCodeGrantRequestEntityConverter.java:42',
    'python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use',
    '10.20.30.41:443/tcp',
    '',
    'abc',
  ]
  it.each(kept)('keeps %j readable', (text) => {
    expect(maskSensitiveText(text)).toBe(text)
  })

  it('is idempotent', () => {
    const inputs = [
      ...masked.map(([, input]) => input),
      ...kept,
      `password=${AWS}).`,
      `private_key=-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAexample\n-----END RSA PRIVATE KEY-----`,
      '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY----- text -----END PRIVATE KEY-----',
      'token=[REDACTED] password=*** secret=AKIA…MPLE https://***@example.com',
    ]
    for (const input of inputs) {
      const once = maskSensitiveText(input)
      expect(maskSensitiveText(once), input).toBe(once)
    }
  })

  it('leaves text that is already masked as it is', () => {
    for (const text of [
      `AKIA${M}7Q2X`,
      '***@example.com',
      'token=[REDACTED]',
      'password=***',
      'secret AKIA…MPLE',
      `https://${M}@git.example.com/a.git`,
    ]) {
      expect(maskSensitiveText(text)).toBe(text)
    }
  })

  it('never throws and takes anything', () => {
    expect(maskSensitiveText(null)).toBe('')
    expect(maskSensitiveText(undefined)).toBe('')
    expect(maskSensitiveText(42 as unknown as string)).toBe('42')
    expect(maskSensitiveText('\uD800 lone surrogate password=\uD800\uD800\uD800\uD800x')).toContain(
      M
    )
  })

  it('masks a whole long value, not only its first part', () => {
    const long = `ghp_${'a1B2'.repeat(500)}`
    expect(maskSensitiveText(`x ${long} y`)).toBe(`x ghp_${M}a1B2 y`)
    const local = `${'a'.repeat(300)}@example.com`
    expect(maskSensitiveText(local)).toBe('***@example.com')
  })

  it('stays fast on 100 kB of adversarial text', () => {
    const n = 100_000
    const cases = [
      'a'.repeat(n),
      'aB3'.repeat(n / 3),
      'a@'.repeat(n / 2),
      '@a.'.repeat(n / 3),
      `${'a.'.repeat(n / 2)}@`,
      `${'a'.repeat(n)}@example.com`,
      '%40'.repeat(n / 3) + 'a.example.com',
      `eyJ${'a'.repeat(n)}`,
      'eyJaaaaaaaa.'.repeat(n / 12),
      `eyJ${'a'.repeat(2047)} `.repeat(n / 2051),
      '-----BEGIN PRIVATE KEY-----'.repeat(n / 27),
      '-----BEGIN PRIVATE KEY----- '.repeat(n / 28) + '-----END PRIVATE KEY-----',
      'password='.repeat(n / 9),
      `password=${' '.repeat(n)}`,
      'password: word '.repeat(n / 15),
      'bearer '.repeat(n / 7),
      `Bearer ${'a-'.repeat(n / 2)}`,
      'https://'.repeat(n / 8),
      `https://${'a:'.repeat(n / 2)}`,
      'a://b@'.repeat(n / 6),
      `${'aB3'.repeat(10)} `.repeat(n / 31),
      'ghp_'.repeat(n / 4),
      'xoxb-'.repeat(n / 5),
      '\n'.repeat(n),
    ]
    const started = performance.now()
    for (const text of cases) {
      const out = maskSensitiveText(text)
      expect(typeof out).toBe('string')
    }
    // Linear work: 24 passes over 100 kB take a few hundred ms at most; a
    // quadratic rule would take minutes.
    expect(performance.now() - started).toBeLessThan(5000)
  })
})

describe('hasSecretMask', () => {
  it('tells a secret preview from other text', () => {
    expect(hasSecretMask(maskSensitiveText(`Key ${AWS}`))).toBe(true)
    expect(hasSecretMask('***@example.com')).toBe(false)
    expect(hasSecretMask(null)).toBe(false)
  })
})
