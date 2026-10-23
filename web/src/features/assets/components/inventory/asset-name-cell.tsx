'use client'

/**
 * The Name cell of the inventory (research/242 D9): one line, cut in the
 * middle so both ends of a long name stay readable (`api-…example.org:443`,
 * `sha256:9f2c…b2d6e9f`), with a copy button that appears on hover or focus
 * and copies the full name. A certificate shows its subject name, with the
 * fingerprint-style asset name in mono below it, and its SANs, issuer and
 * expiry in the tooltip, so a certificate is found by the site it serves.
 *
 * Every value here is discovered data: React text only, through
 * `toDisplayText`, never markup.
 */

import { useState, type MouseEvent } from 'react'
import { Check, Copy } from 'lucide-react'
import Link from '@/components/link'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'
import { middleEllipsis } from '@/lib/middle-ellipsis'
import { safeHref } from '@/lib/safe-href'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { AssetTypeIcon } from '../../lib/asset-type-icon'
import { certDaysLeft, certIssuer, certSans, certSubject } from '../../lib/certificate-facts'
import type { Asset } from '../../types'

/** Characters of a name before it is cut in the middle. */
export const NAME_MAX = 48
/** SANs listed in the tooltip before "+N more". */
const SANS_SHOWN = 6

export function AssetNameCell({
  asset,
  href,
  onOpen,
}: {
  asset: Asset
  href: string
  /** Plain click opens the drawer; the link still works for new tabs. */
  onOpen: (e: MouseEvent<HTMLAnchorElement>) => void
}) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const name = toDisplayText(asset.name)
  const isCert = asset.type === 'certificate'
  const subject = isCert ? certSubject(asset) : undefined
  // A certificate whose name is its subject needs no second line.
  const title = subject && subject !== asset.name ? toDisplayText(subject) : name
  const subLine = title !== name ? name : undefined

  const copy = async (e: MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation()
    if (await copyToClipboard(asset.name)) {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    }
  }

  const sans = isCert ? certSans(asset) : []
  const issuer = isCert ? certIssuer(asset) : undefined
  const days = isCert ? certDaysLeft(asset) : null

  return (
    <div className="group/name flex min-w-0 items-center gap-2" data-testid="asset-name-cell">
      <AssetTypeIcon type={asset.type} className="h-4 w-4 shrink-0 text-muted-foreground" />
      <Tooltip>
        <TooltipTrigger asChild>
          <div className="grid min-w-0">
            <Link
              href={safeHref(href) ?? '/assets'}
              onClick={onOpen}
              dir="auto"
              aria-label={name}
              className="truncate font-medium [unicode-bidi:isolate] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {middleEllipsis(title, NAME_MAX)}
            </Link>
            {subLine && (
              <span
                dir="auto"
                className="truncate font-mono text-xs text-muted-foreground [unicode-bidi:isolate]"
              >
                {middleEllipsis(subLine, NAME_MAX)}
              </span>
            )}
          </div>
        </TooltipTrigger>
        <TooltipContent className="max-w-[min(28rem,90vw)] space-y-1 text-start">
          <p className="font-medium break-all" dir="auto">
            {title}
          </p>
          {isCert && issuer && (
            <p className="flex flex-wrap gap-x-2 text-xs opacity-80">
              <span>
                {t('assets.nameCell.issuer', 'Issuer {issuer}', { issuer: toDisplayText(issuer) })}
              </span>
              {days !== null && (
                <span>
                  {days < 0
                    ? t('assets.nameCell.expired', 'expired')
                    : t(
                        'assets.nameCell.expiresIn',
                        'expires in {count, plural, one {# day} other {# days}}',
                        { count: days }
                      )}
                </span>
              )}
            </p>
          )}
          {sans.length > 0 && (
            <p className="text-xs break-all opacity-80">
              {t('assets.nameCell.sans', 'Also names: {names}', {
                names:
                  sans
                    .slice(0, SANS_SHOWN)
                    .map((s) => toDisplayText(s))
                    .join(', ') + (sans.length > SANS_SHOWN ? ` +${sans.length - SANS_SHOWN}` : ''),
              })}
            </p>
          )}
          {subLine && <p className="font-mono text-xs break-all opacity-80">{subLine}</p>}
        </TooltipContent>
      </Tooltip>
      <button
        type="button"
        onClick={copy}
        aria-label={
          copied
            ? t('assets.nameCell.copied', 'Copied')
            : t('assets.nameCell.copy', 'Copy {name}', { name })
        }
        className={cn(
          'ms-auto inline-flex size-6 shrink-0 items-center justify-center rounded text-muted-foreground opacity-0 hover:bg-muted hover:text-foreground focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring group-hover/name:opacity-100',
          copied && 'opacity-100'
        )}
      >
        {copied ? (
          <Check className="size-3.5" aria-hidden />
        ) : (
          <Copy className="size-3.5" aria-hidden />
        )}
      </button>
    </div>
  )
}
