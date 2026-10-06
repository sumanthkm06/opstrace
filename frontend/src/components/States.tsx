/** Reusable state-display primitives */

export function LoadingState({ message = 'Loading…' }: { message?: string }) {
  return (
    <div className="loading-state">
      <div className="spinner" />
      {message}
    </div>
  )
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="error-state">
      <span style={{ fontSize: '1.5rem' }}>⚠</span>
      <span>{message}</span>
    </div>
  )
}

export function EmptyState({ title, sub, icon = '🗂' }: { title: string; sub?: string; icon?: string }) {
  return (
    <div className="empty-state">
      <span className="empty-icon">{icon}</span>
      <span className="empty-title">{title}</span>
      {sub && <span className="empty-sub">{sub}</span>}
    </div>
  )
}
