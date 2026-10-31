'use client'

import { useEffect, useState } from 'react'
import { Maximize, Minimize } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Header button that toggles browser full-screen via the Fullscreen API.
 * Hides browser chrome (URL/tab bar) for an immersive dashboard.
 *
 * Renders nothing where the Fullscreen API isn't available (e.g. iOS Safari,
 * which doesn't expose it for arbitrary elements) so there's no dead button,
 * and is hidden below the md breakpoint (phones).
 */
export function FullscreenToggle() {
  const { t } = useTranslation()
  const [supported, setSupported] = useState(false)
  const [isFullscreen, setIsFullscreen] = useState(false)

  useEffect(() => {
    setSupported(Boolean(document.fullscreenEnabled))
    const onChange = () => setIsFullscreen(Boolean(document.fullscreenElement))
    document.addEventListener('fullscreenchange', onChange)
    return () => document.removeEventListener('fullscreenchange', onChange)
  }, [])

  if (!supported) return null

  const toggle = () => {
    if (document.fullscreenElement) {
      void document.exitFullscreen?.()
    } else {
      void document.documentElement.requestFullscreen?.()
    }
  }

  const Icon = isFullscreen ? Minimize : Maximize
  const label = isFullscreen
    ? t('nav.header.exitFullScreen', 'Exit full screen')
    : t('nav.header.fullScreen', 'Full screen')

  return (
    <Button
      variant="ghost"
      size="icon"
      // Not on a phone: the top bar is full there, and a phone browser either
      // has no Fullscreen API for pages or hides its chrome on scroll anyway.
      className="relative hidden scale-95 rounded-full md:inline-flex"
      onClick={toggle}
      aria-label={label}
      title={label}
    >
      <Icon className="size-[1.2rem]" />
      <span className="sr-only">{label}</span>
    </Button>
  )
}
