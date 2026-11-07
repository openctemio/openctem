/**
 * Renders the extension's replacement for one of the replaceable core
 * components (ExtensionOverrideProps in ./types.ts), or the core component
 * itself; always the core component in the default build.
 */
import type { ComponentType } from 'react'

import { webExtension } from './index'
import type { ExtensionOverrideId, ExtensionOverrideProps } from './types'

type OverridableProps<K extends ExtensionOverrideId> = {
  id: K
  fallback: ComponentType<ExtensionOverrideProps[K]>
} & ExtensionOverrideProps[K]

export function Overridable<K extends ExtensionOverrideId>({
  id,
  fallback,
  ...props
}: OverridableProps<K>) {
  const Component = (webExtension.overrides[id] ?? fallback) as ComponentType<
    ExtensionOverrideProps[K]
  >
  return <Component {...(props as unknown as ExtensionOverrideProps[K])} />
}
