'use client'

import { Logo, LogoFull } from '@/assets/logo'
import { useBrand } from '@/context/brand-provider'
import { useTranslation } from '@/context/i18n-provider'
import { UPSTREAM_NAME, type Brand } from '@/lib/brand'
import { safeImageSrc } from '@/lib/safe-href'
import { cn } from '@/lib/utils'

/**
 * The brand's logo in the console: the configured image (light and dark
 * variants follow the theme), or the built-in mark when the brand has none.
 * The image paths were validated as same-origin brand asset paths
 * (src/lib/brand.ts) and are rendered with <img>, which never runs script.
 */
interface MarkProps {
  className?: string
  'aria-hidden'?: boolean
  'data-slot'?: string
}

function BrandImage({ brand, className, ...rest }: MarkProps & { brand: Brand }) {
  if (!safeImageSrc(brand.logoLightUrl)) return null
  return (
    <>
      {/* eslint-disable-next-line @next/next/no-img-element -- a small operator image served by the API */}
      <img
        src={safeImageSrc(brand.logoLightUrl)}
        alt={rest['aria-hidden'] ? '' : brand.name}
        className={cn('w-auto object-contain dark:hidden', className)}
        {...rest}
      />
      {/* eslint-disable-next-line @next/next/no-img-element -- a small operator image served by the API */}
      <img
        src={safeImageSrc(brand.logoDarkUrl || brand.logoLightUrl)}
        alt={rest['aria-hidden'] ? '' : brand.name}
        className={cn('hidden w-auto object-contain dark:block', className)}
        {...rest}
      />
    </>
  )
}

/** A square mark (collapsed sidebar, next to the name). */
export function BrandMark({ className, ...rest }: MarkProps) {
  const brand = useBrand()
  if (brand.logoLightUrl) return <BrandImage brand={brand} className={className} {...rest} />
  if (brand.name === UPSTREAM_NAME) {
    return <Logo className={className} aria-label={brand.name} {...rest} />
  }
  // A renamed brand without a logo: its initial, never the built-in mark.
  return (
    <span
      role="img"
      aria-label={brand.name}
      {...rest}
      className={cn(
        'inline-flex items-center justify-center rounded-md bg-primary font-semibold text-primary-foreground',
        className
      )}
    >
      {brand.shortName.slice(0, 1).toUpperCase()}
    </span>
  )
}

/** The horizontal logo (sign-in, legal pages, console sign-in). */
export function BrandLogoFull({ className }: { className?: string }) {
  const brand = useBrand()
  if (brand.logoLightUrl) return <BrandImage brand={brand} className={className} />
  if (brand.name === UPSTREAM_NAME)
    return <LogoFull className={className} aria-label={brand.name} />
  return (
    <span
      className="text-3xl font-semibold tracking-tight sm:text-4xl"
      role="img"
      aria-label={brand.name}
    >
      {brand.name}
    </span>
  )
}

/** "Powered by OpenCTEM" under a renamed brand, when the operator keeps the credit. */
export function PoweredBy({ className }: { className?: string }) {
  const brand = useBrand()
  const { t } = useTranslation()
  if (!brand.poweredBy) return null
  return (
    <p className={cn('text-center text-xs text-muted-foreground', className)}>
      {t('brand.poweredBy', undefined, { upstream: UPSTREAM_NAME })}
    </p>
  )
}
