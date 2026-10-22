'use client'

import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Card } from '@/components/ui/card'
import { WidgetError } from './widget-error'

interface WidgetBoundaryProps {
  children: ReactNode
  /** Shown in place of a card that threw while rendering (default: a card with Retry). */
  fallback?: (reset: () => void) => ReactNode
}

interface WidgetBoundaryState {
  failed: boolean
}

/**
 * One dashboard card that throws while rendering (a malformed payload, a
 * missing field) shows its own error state with Retry; the rest of the
 * dashboard keeps rendering. Without it one bad part blanked the whole page.
 */
export class WidgetBoundary extends Component<WidgetBoundaryProps, WidgetBoundaryState> {
  state: WidgetBoundaryState = { failed: false }

  static getDerivedStateFromError(): WidgetBoundaryState {
    return { failed: true }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Development aid only; nothing user-provided is logged.
    if (process.env.NODE_ENV !== 'production') {
      console.error('dashboard widget failed to render', error, info.componentStack)
    }
  }

  private reset = () => this.setState({ failed: false })

  render() {
    if (!this.state.failed) return this.props.children
    if (this.props.fallback) return this.props.fallback(this.reset)
    return (
      <Card className="h-full p-4">
        <WidgetError onRetry={this.reset} />
      </Card>
    )
  }
}
