import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

// Last line of defense for the dashboard. A render-time throw anywhere below
// this boundary would otherwise unmount the entire React tree and leave only
// the dark page background (a black screen). Catching it keeps a readable
// message and a reload control on screen, and logs the error so it surfaces in
// the console instead of silently swallowing the UI. The streaming engine keeps
// running regardless, so a reload reconnects and rebuilds the view.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('[Unravel] UI error boundary caught:', error, info.componentStack)
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div
          role="alert"
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 12,
            alignItems: 'flex-start',
            padding: '48px 56px',
            maxWidth: 720,
            margin: '0 auto',
            color: '#dce4ec',
            fontFamily: '"JetBrains Mono", "Fira Code", monospace',
          }}
        >
          <h1 style={{ fontSize: 20, margin: 0, color: '#f8be34' }}>
            Unravel hit a rendering error
          </h1>
          <p style={{ margin: 0, lineHeight: 1.5 }}>
            The engine is still running. Reload to reconnect and rebuild the view.
          </p>
          <pre
            style={{
              margin: 0,
              padding: '12px 16px',
              background: '#12171c',
              border: '1px solid #2b3640',
              borderRadius: 6,
              color: '#ffb4ab',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              maxWidth: '100%',
            }}
          >
            {this.state.error.message}
          </pre>
          <button
            type="button"
            onClick={() => window.location.reload()}
            style={{
              padding: '8px 18px',
              background: '#1c2530',
              color: '#dce4ec',
              border: '1px solid #3a4856',
              borderRadius: 6,
              cursor: 'pointer',
              fontFamily: 'inherit',
            }}
          >
            Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
