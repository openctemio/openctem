import { cn } from '@/lib/utils'

/**
 * Where the operator's terms and privacy policy live: documents hosted
 * elsewhere (LEGAL_TERMS_URL / LEGAL_PRIVACY_URL) or the built-in templates
 * at /terms and /privacy (LEGAL_PAGES_ENABLED=true). The server pages pass
 * them in (src/lib/legal.ts); the notice shows only what is configured, so
 * nothing links to a 404.
 */
const TERMS_URL = process.env.NEXT_PUBLIC_TERMS_URL || ''
const PRIVACY_URL = process.env.NEXT_PUBLIC_PRIVACY_URL || ''

interface LegalNoticeProps {
  /** What the visitor is doing: "clicking sign in", "creating an account". */
  action: string
  termsUrl?: string
  privacyUrl?: string
  className?: string
}

const linkClass = 'hover:text-primary underline underline-offset-4'

/** "By <action>, you agree to our Terms of Service and Privacy Policy." */
export function LegalNotice({
  action,
  termsUrl = TERMS_URL,
  privacyUrl = PRIVACY_URL,
  className,
}: LegalNoticeProps) {
  if (!termsUrl && !privacyUrl) return null

  const terms = termsUrl ? (
    <a href={termsUrl} target="_blank" rel="noopener noreferrer" className={linkClass}>
      Terms of Service
    </a>
  ) : null
  const privacy = privacyUrl ? (
    <a href={privacyUrl} target="_blank" rel="noopener noreferrer" className={linkClass}>
      Privacy Policy
    </a>
  ) : null

  return (
    <p className={cn('text-muted-foreground px-8 text-center text-sm', className)}>
      By {action}, you agree to our {terms}
      {terms && privacy ? ' and ' : null}
      {privacy}.
    </p>
  )
}
