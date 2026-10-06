import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { healthApi } from '../services/api'
import type { APIHealthResponse } from '../types'

const NAV = [
  { to: '/overview', icon: '◈', label: 'Overview' },
  { to: '/hosts', icon: '⬡', label: 'Hosts' },
  { to: '/services', icon: '⚙', label: 'Services' },
  { to: '/incidents', icon: '⚡', label: 'Incidents' },
  { to: '/logs', icon: '📋', label: 'Logs & Analysis' },
  { to: '/dependencies', icon: '⛶', label: 'Dependencies' },
]

const PAGE_TITLES: Record<string, string> = {
  '/overview': 'Overview',
  '/hosts': 'Hosts',
  '/services': 'Services',
  '/incidents': 'Incidents',
  '/logs': 'Logs & Analysis',
  '/dependencies': 'Dependency Impact',
}

function useHealth() {
  const [health, setHealth] = useState<APIHealthResponse | null>(null)
  const [status, setStatus] = useState<'loading' | 'ok' | 'degraded' | 'error'>('loading')

  useEffect(() => {
    healthApi.get()
      .then(h => { setHealth(h); setStatus(h.status as 'ok' | 'degraded') })
      .catch(() => setStatus('error'))
  }, [])

  return { health, status }
}

export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation()
  const { health, status } = useHealth()

  const pageTitle =
    Object.entries(PAGE_TITLES).find(([path]) => location.pathname.startsWith(path))?.[1] ?? 'OpsTrace'

  return (
    <div className="layout">
      {/* Sidebar */}
      <nav className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">⚡</div>
          <span className="brand-name">OpsTrace</span>
        </div>

        <div className="sidebar-nav">
          <div className="nav-section-label">Navigation</div>
          {NAV.map(({ to, icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              <span className="nav-icon">{icon}</span>
              {label}
            </NavLink>
          ))}
        </div>

        <div className="sidebar-footer">
          v{health?.version ?? '…'} · {health?.environment ?? '…'}
        </div>
      </nav>

      {/* Main */}
      <div className="main-area">
        <header className="topbar">
          <span className="topbar-title">{pageTitle}</span>
          <div className="topbar-right">
            {status === 'loading' ? (
              <span className="health-pill unknown"><span className="dot" />Connecting…</span>
            ) : (
              <span className={`health-pill ${status}`}>
                <span className={`dot${status === 'ok' ? ' pulse' : ''}`} />
                {status === 'ok' ? 'Backend OK' : status === 'degraded' ? 'Degraded' : 'Unavailable'}
              </span>
            )}
          </div>
        </header>

        <main className="page-content">
          {children}
        </main>
      </div>
    </div>
  )
}
