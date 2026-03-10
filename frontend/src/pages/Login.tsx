import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Mail, Lock, Eye, EyeOff, ArrowRight } from 'lucide-react';
import toast from 'react-hot-toast';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await login({ email, password });
      toast.success('Welcome back!');
      navigate('/');
    } catch {
      toast.error('Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 flex">
      {/* Left side — branding */}
      <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden bg-slate-800">
        <div className="absolute inset-0 bg-gradient-to-br from-blue-900/20 via-slate-800 to-slate-800" />

        <div className="relative z-10 flex flex-col justify-center px-16">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-12 h-12 rounded-lg bg-blue-600 flex items-center justify-center">
              <Shield size={24} className="text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Guardian Shield</h1>
              <p className="text-sm text-slate-400">Context-Aware ML Firewall</p>
            </div>
          </div>

          <div className="space-y-5 max-w-md">
            <h2 className="text-3xl font-bold text-slate-100 leading-tight">
              Intelligent network protection powered by{' '}
              <span className="text-blue-400">
                machine learning
              </span>
            </h2>
            <p className="text-slate-400 text-base leading-relaxed">
              Real-time traffic analysis, anomaly detection, and context-aware policy enforcement
              to keep your network secure.
            </p>

            <div className="flex gap-8 pt-4">
              {[
                { label: 'Threats Blocked', value: '12.4K' },
                { label: 'ML Accuracy', value: '97.2%' },
                { label: 'Response Time', value: '<50ms' },
              ].map((stat) => (
                <div key={stat.label}>
                  <p className="text-xl font-bold text-slate-100">{stat.value}</p>
                  <p className="text-xs text-slate-500">{stat.label}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Right side — login form */}
      <div className="flex-1 flex items-center justify-center px-6">
        <div className="w-full max-w-sm">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center justify-center gap-3 mb-10">
            <div className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center">
              <Shield size={20} className="text-white" />
            </div>
            <h1 className="text-xl font-bold text-slate-100">
              Guardian Shield
            </h1>
          </div>

          <div className="mb-8">
            <h2 className="text-xl font-semibold text-slate-100 mb-1">Welcome back</h2>
            <p className="text-slate-500 text-sm">Enter your credentials to access the dashboard</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300">Email</label>
              <div className="relative">
                <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@company.com"
                  className="w-full bg-slate-800 border border-slate-600 rounded-md pl-10 pr-4 py-2.5 text-sm text-slate-200
                    placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50
                    transition-colors"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300">Password</label>
              <div className="relative">
                <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full bg-slate-800 border border-slate-600 rounded-md pl-10 pr-11 py-2.5 text-sm text-slate-200
                    placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50
                    transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-blue-600
                hover:bg-blue-700 text-white font-medium py-2.5 rounded-md
                shadow-sm transition-colors duration-150
                disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : (
                <>
                  Sign In
                  <ArrowRight size={18} />
                </>
              )}
            </button>
          </form>

          <p className="text-center text-slate-500 text-sm mt-8">
            Don't have an account?{' '}
            <Link to="/register" className="text-blue-400 hover:text-blue-300 font-medium transition-colors">
              Create one
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
