import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  FolderKanban,
  FileSearch,
  Clock,
  Bell,
  Flag,
  FileText,
  ScrollText,
  Settings,
  ShieldCheck,
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/cases', label: 'Cases', icon: FolderKanban },
  { to: '/evidence', label: 'Evidence', icon: FileSearch },
  { to: '/timeline', label: 'Timeline', icon: Clock },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/indicators', label: 'Indicators', icon: Flag },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/audit-logs', label: 'Audit Logs', icon: ScrollText },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export default function Sidebar() {
  const { profile } = useAuth()

  return (
    <aside className="w-64 h-full bg-soc-surface border-r border-soc-border flex flex-col flex-shrink-0">
      {/* Logo */}
      <div className="h-16 flex items-center gap-2 px-5 border-b border-soc-border">
        <ShieldCheck className="w-7 h-7 text-accent-cyan" />
        <div className="flex flex-col">
          <span className="text-sm font-bold text-soc-text leading-tight">
            Evidence Analyzer
          </span>
          <span className="text-[10px] text-soc-muted leading-tight">
            Digital Forensics Platform
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors duration-200 ${
                  isActive
                    ? 'bg-accent-blue/15 text-accent-blue border-l-2 border-accent-blue'
                    : 'text-soc-muted hover:bg-soc-hover hover:text-soc-text'
                }`
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          )
        })}
      </nav>

      {/* User info */}
      {profile && (
        <div className="border-t border-soc-border p-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full bg-accent-blue/20 flex items-center justify-center text-accent-blue font-semibold text-sm">
              {profile.name.charAt(0).toUpperCase()}
            </div>
            <div className="flex flex-col min-w-0">
              <span className="text-sm font-medium text-soc-text truncate">
                {profile.name}
              </span>
              <span className="text-xs text-soc-muted truncate">
                {profile.role}
              </span>
            </div>
          </div>
        </div>
      )}
    </aside>
  )
}
