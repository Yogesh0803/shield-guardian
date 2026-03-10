import React, { useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard,
  Server,
  Shield,
  AlertTriangle,
  Activity,
  Brain,
  Menu,
  X,
  LogOut,
  ChevronLeft,
  User,
} from 'lucide-react';

const navItems = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/endpoints', icon: Server, label: 'Endpoints' },
  { path: '/policies', icon: Shield, label: 'Policies' },
  { path: '/alerts', icon: AlertTriangle, label: 'Alerts' },
  { path: '/network', icon: Activity, label: 'Network' },
  { path: '/ml', icon: Brain, label: 'ML Engine' },
];

export const DashboardLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200">
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed top-0 left-0 h-full z-50 bg-slate-800 border-r border-slate-700
          transition-all duration-200 flex flex-col
          ${sidebarOpen ? 'w-60' : 'w-[68px]'}
          ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-5 border-b border-slate-700">
          <div className="relative flex-shrink-0">
            <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center">
              <Shield size={18} className="text-white" />
            </div>
            <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-400 rounded-full border-2 border-slate-800" />
          </div>
          {sidebarOpen && (
            <div className="overflow-hidden">
              <h1 className="text-sm font-semibold text-slate-100 leading-tight">
                Guardian Shield
              </h1>
              <p className="text-[10px] text-slate-500 uppercase tracking-wider">Firewall Console</p>
            </div>
          )}
        </div>

        {/* Nav links */}
        <nav className="flex-1 px-3 py-3 space-y-0.5 overflow-y-auto">
          {navItems.map(({ path, icon: Icon, label }) => (
            <NavLink
              key={path}
              to={path}
              end={path === '/'}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md transition-colors duration-150 group
                ${
                  isActive
                    ? 'bg-blue-600/10 text-blue-400 font-medium'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
                }`
              }
            >
              <Icon size={18} className="flex-shrink-0" />
              {sidebarOpen && <span className="text-sm">{label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* User section */}
        <div className="border-t border-slate-700 p-3">
          {sidebarOpen ? (
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-md bg-slate-600 flex items-center justify-center text-xs font-semibold text-slate-200 flex-shrink-0">
                {user?.name?.charAt(0).toUpperCase() || 'U'}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-200 truncate">{user?.name || 'User'}</p>
                <p className="text-xs text-slate-500 truncate">{user?.role || 'admin'}</p>
              </div>
              <button
                onClick={handleLogout}
                className="p-1.5 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                title="Logout"
              >
                <LogOut size={15} />
              </button>
            </div>
          ) : (
            <button
              onClick={handleLogout}
              className="w-full flex items-center justify-center p-2 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
              title="Logout"
            >
              <LogOut size={16} />
            </button>
          )}
        </div>

        {/* Collapse toggle (desktop) */}
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="hidden lg:flex absolute -right-3 top-20 w-6 h-6 bg-slate-800 border border-slate-600 rounded-full
            items-center justify-center text-slate-400 hover:text-slate-200 transition-colors"
        >
          <ChevronLeft size={14} className={`transition-transform duration-200 ${sidebarOpen ? '' : 'rotate-180'}`} />
        </button>
      </aside>

      {/* Main content */}
      <main className={`transition-all duration-200 ${sidebarOpen ? 'lg:ml-60' : 'lg:ml-[68px]'}`}>
        {/* Top bar */}
        <header className="sticky top-0 z-30 bg-slate-900 border-b border-slate-800">
          <div className="flex items-center justify-between px-6 py-2.5">
            <button
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-2 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
            >
              <Menu size={20} />
            </button>
            <div className="flex items-center gap-3 ml-auto">
              <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/20">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                <span className="text-xs font-medium text-emerald-400">Active</span>
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <div className="p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
};
