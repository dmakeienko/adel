import { useEffect, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { User, Users, UsersRound, Lock, LogOut } from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import { useNotification } from '../contexts/NotificationContext';
import { Separator } from '@/components/ui/separator';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';

export function Sidebar() {
  const { user, logout, isAuthenticated, canSearch, isLead } = useAuth();
  const { showNotification } = useNotification();
  const navigate = useNavigate();
  const [version, setVersion] = useState<string | null>(null);

  // Fetched once per mount; /health is public, so this works regardless of session state.
  useEffect(() => {
    let cancelled = false;
    api.getVersion().then((v) => {
      if (!cancelled) {
        setVersion(v);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!isAuthenticated || !user) {
    return null;
  }

  const handleLogout = async () => {
    await logout();
    showNotification('You have been logged out successfully', 'info');
    navigate('/');
  };

  const initials =
    (user.givenName?.charAt(0) || user.sAMAccountName.charAt(0)) +
    (user.sn?.charAt(0) || '');

  return (
    <aside className="fixed top-0 left-0 w-64 h-screen flex flex-col bg-sidebar py-6 px-4 overflow-y-auto border-r border-sidebar-border">
      {/* Logo */}
      <div className="flex items-center justify-center px-2 mb-8">
        <img src="/logo.svg" alt="ADEL" className="w-24 h-24" />
      </div>

      {/* Nav */}
      <nav className="flex-1 flex flex-col gap-1">
        <NavLink
          to={`/user/${user.sAMAccountName}`}
          className={({ isActive }) =>
            `flex items-center gap-3 px-4 py-3 text-sm font-medium transition-colors no-underline ${
              isActive
                ? 'bg-sidebar-accent text-sidebar-foreground'
                : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground'
            }`
          }
        >
          <User className="w-5 h-5 shrink-0" />
          My Account
        </NavLink>

        {/* Only leads and PMs have a team, so the tab is hidden for everyone else
            rather than leading to an empty page. */}
        {isLead && (
          <NavLink
            to="/team"
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 text-sm font-medium transition-colors no-underline ${
                isActive
                  ? 'bg-sidebar-accent text-sidebar-foreground'
                  : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground'
              }`
            }
          >
            <UsersRound className="w-5 h-5 shrink-0" />
            Team
          </NavLink>
        )}

        {/* Group browsing hits the same gated endpoints as search, so users without
            that permission are not offered a tab that can only fail. */}
        {canSearch && (
          <NavLink
            to="/groups"
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 text-sm font-medium transition-colors no-underline ${
                isActive
                  ? 'bg-sidebar-accent text-sidebar-foreground'
                  : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground'
              }`
            }
          >
            <Users className="w-5 h-5 shrink-0" />
            Groups
          </NavLink>
        )}

        <NavLink
          to="/change-password"
          className={({ isActive }) =>
            `flex items-center gap-3 px-4 py-3 text-sm font-medium transition-colors no-underline ${
              isActive
                ? 'bg-sidebar-accent text-sidebar-foreground'
                : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground'
            }`
          }
        >
          <Lock className="w-5 h-5 shrink-0" />
          Change My Password
        </NavLink>

        <button
          className="flex items-center gap-3 px-4 py-3 w-full text-sm font-medium transition-colors text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground mt-auto"
          onClick={handleLogout}
        >
          <LogOut className="w-5 h-5 shrink-0" />
          Log Out
        </button>
      </nav>

      <Separator className="bg-sidebar-border my-4" />

      {/* User info */}
      <div className="flex items-center gap-3 px-4 py-3 bg-sidebar-accent/50 rounded-lg">
        <Avatar className="w-10 h-10 shrink-0">
          <AvatarFallback className="font-semibold text-sm uppercase">
            {initials}
          </AvatarFallback>
        </Avatar>
        <div className="flex flex-col overflow-hidden">
          <span className="text-sidebar-foreground text-sm font-medium truncate">
            {user.displayName || user.sAMAccountName}
          </span>
          <span className="text-sidebar-foreground/60 text-xs truncate">{user.mail}</span>
        </div>
      </div>

      {/* Product version */}
      {version && (
        <div className="px-4 pt-3 text-left text-xs text-sidebar-foreground/50">
          ADEL v{version}
        </div>
      )}
    </aside>
  );
}
