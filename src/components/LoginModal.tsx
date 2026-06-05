import React, { useState } from 'react';
import { Shield, Mail, Lock, Check, RefreshCw, X, ArrowRight, UserPlus, LogIn } from 'lucide-react';
import { User } from '../types.js';

interface LoginModalProps {
  onClose: () => void;
  onLoginSuccess: (token: string, user: User) => void;
}

type Mode = 'login' | 'register';

export default function LoginModal({ onClose, onLoginSuccess }: LoginModalProps) {
  const [mode, setMode] = useState<Mode>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes('@') || password.length < 8) return;

    setError('');
    setIsSubmitting(true);

    try {
      const endpoint = mode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.message || data.error || 'Authentication failed. Please try again.');
        return;
      }

      setSuccess(true);
      setTimeout(() => {
        onLoginSuccess(data.token, data.user);
        onClose();
      }, 800);
    } catch {
      setError('Network error. Please check your connection and try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const toggleMode = () => {
    setMode(m => m === 'login' ? 'register' : 'login');
    setError('');
  };

  const isValid = email.includes('@') && password.length >= 8;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div
        className="relative w-full max-w-md bg-[#0c0c0e] border border-[#27272a] p-8 rounded shadow-2xl space-y-6"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1 rounded text-[#52525b] hover:text-white transition-colors cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="text-center space-y-2">
          <div className="inline-flex p-2 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded text-[#22c55e] mb-2">
            <Shield className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-bold font-mono text-white">
            {mode === 'login' ? 'Sign In to Seclayer' : 'Create Account'}
          </h2>
          <p className="text-[#a1a1aa] text-xs max-w-xs mx-auto font-mono">
            {mode === 'login'
              ? 'Enter your credentials to access your security dashboard.'
              : 'New accounts receive <strong class="text-[#22c55e]">5 free scan credits</strong> to get started.'}
          </p>
        </div>

        {success ? (
          <div className="bg-[#22c55e]/5 border border-[#22c55e]/25 p-5 rounded text-center space-y-2 text-[#22c55e]">
            <Check className="w-6 h-6 mx-auto bg-[#22c55e] text-black rounded-full p-1" />
            <span className="text-xs font-mono font-bold block uppercase tracking-wider">
              {mode === 'login' ? 'Authenticated' : 'Account created'}
            </span>
            <p className="text-[11px] text-[#a1a1aa] font-mono">Loading your security dashboard...</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-[10px] font-mono text-[#52525b] uppercase block mb-1.5 ml-1">Email address</label>
              <div className="flex bg-black border border-[#27272a] rounded p-2.5 focus-within:border-[#22c55e] transition-colors">
                <Mail className="w-4 h-4 text-[#52525b] mr-2 shrink-0 self-center" />
                <input
                  type="email"
                  required
                  placeholder="name@company.com"
                  className="bg-transparent text-white text-xs font-mono w-full focus:outline-none"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={isSubmitting}
                  autoComplete="email"
                />
              </div>
            </div>

            <div>
              <label className="text-[10px] font-mono text-[#52525b] uppercase block mb-1.5 ml-1">
                Password {mode === 'register' && <span className="text-[#3f3f46]">(min. 8 characters)</span>}
              </label>
              <div className="flex bg-black border border-[#27272a] rounded p-2.5 focus-within:border-[#22c55e] transition-colors">
                <Lock className="w-4 h-4 text-[#52525b] mr-2 shrink-0 self-center" />
                <input
                  type="password"
                  required
                  minLength={8}
                  placeholder="••••••••"
                  className="bg-transparent text-white text-xs font-mono w-full focus:outline-none"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isSubmitting}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                />
              </div>
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/25 rounded p-3 text-red-400 text-xs font-mono">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting || !isValid}
              className="w-full py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono tracking-widest uppercase font-bold rounded transition-all flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Authenticating...</span>
                </>
              ) : mode === 'login' ? (
                <>
                  <LogIn className="w-3.5 h-3.5" />
                  <span>Sign In</span>
                </>
              ) : (
                <>
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Create Account</span>
                </>
              )}
            </button>

            <p className="text-center text-[11px] font-mono text-[#52525b]">
              {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}{' '}
              <button
                type="button"
                onClick={toggleMode}
                className="text-[#22c55e] hover:underline cursor-pointer"
              >
                {mode === 'login' ? 'Create one' : 'Sign in'}
              </button>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}
