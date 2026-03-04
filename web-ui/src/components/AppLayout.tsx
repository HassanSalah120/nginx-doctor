import { NavLink, Outlet } from 'react-router-dom'

const navItems = [
  { to: '/', label: 'Dashboard' },
  { to: '/servers', label: 'Servers' },
  { to: '/jobs', label: 'Jobs' },
  { to: '/settings/integrations', label: 'Integrations' },
  { to: '/settings/daemon', label: 'Daemon' },
  { to: '/kubernetes', label: 'Kubernetes' },
]

function NavItem({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      end={to === '/'}
      className={({ isActive }) =>
        [
          'flex items-center rounded-md px-3 py-2 text-sm font-medium transition',
          isActive
            ? 'bg-slate-800 text-white'
            : 'text-slate-300 hover:bg-slate-900 hover:text-white',
        ].join(' ')
      }
    >
      {label}
    </NavLink>
  )
}

export default function AppLayout() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-7xl">
        <aside className="hidden w-64 flex-col border-r border-slate-900 p-4 md:flex">
          <div className="mb-6">
            <div className="text-lg font-semibold tracking-tight">NginxDoctor</div>
            <div className="text-xs text-slate-400">Local infrastructure diagnosis</div>
          </div>

          <nav className="flex flex-col gap-1">
            {navItems.map((i) => (
              <NavItem key={i.to} to={i.to} label={i.label} />
            ))}
          </nav>

          <div className="mt-auto pt-6 text-xs text-slate-500">
            Runs on localhost only
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-10 border-b border-slate-900 bg-slate-950/70 backdrop-blur">
            <div className="flex items-center justify-between px-4 py-3 md:px-6">
              <div className="text-sm font-medium text-slate-200">AI Infrastructure Diagnosis Platform</div>
              <a
                className="text-xs text-slate-400 hover:text-slate-200"
                href="/api/docs"
                target="_blank"
                rel="noreferrer"
              >
                API Docs
              </a>
            </div>
          </header>

          <main className="flex-1 px-4 py-6 md:px-6">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  )
}
