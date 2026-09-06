import { Search, Bell, ChevronDown } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { useNavigate } from 'react-router-dom'
import { useState, useRef, useEffect } from 'react'

export default function Topbar() {
  const { profile, signOut } = useAuth()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  return (
    <header className="h-16 bg-soc-surface border-b border-soc-border flex items-center justify-between px-6 flex-shrink-0">
      {/* Search */}
      <div className="relative flex-1 max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-muted" />
        <input
          type="text"
          placeholder="Search cases, evidence, indicators..."
          className="w-full pl-9 pr-4 py-2 bg-soc-bg border border-soc-border rounded-md text-sm text-soc-text placeholder-soc-muted focus:outline-none focus:border-accent-blue transition-colors"
        />
      </div>

      {/* Right side */}
      <div className="flex items-center gap-4 ml-6">
        <button className="relative p-2 text-soc-muted hover:text-soc-text transition-colors">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-severity-high rounded-full"></span>
        </button>

        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setMenuOpen(!menuOpen)}
            className="flex items-center gap-2 text-sm text-soc-muted hover:text-soc-text transition-colors"
          >
            <div className="w-8 h-8 rounded-full bg-accent-blue/20 flex items-center justify-center text-accent-blue font-semibold text-xs">
              {profile?.name.charAt(0).toUpperCase() ?? '?'}
            </div>
            <span className="hidden sm:inline">{profile?.name}</span>
            <ChevronDown className="w-4 h-4" />
          </button>

          {menuOpen && (
            <div className="absolute right-0 top-12 w-48 bg-soc-card border border-soc-border rounded-md shadow-lg py-1 z-50 animate-fade-in">
              <button
                onClick={() => {
                  setMenuOpen(false)
                  navigate('/profile')
                }}
                className="w-full text-left px-4 py-2 text-sm text-soc-muted hover:bg-soc-hover hover:text-soc-text transition-colors"
              >
                Profile
              </button>
              <button
                onClick={() => {
                  setMenuOpen(false)
                  signOut()
                }}
                className="w-full text-left px-4 py-2 text-sm text-severity-critical hover:bg-soc-hover transition-colors"
              >
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
