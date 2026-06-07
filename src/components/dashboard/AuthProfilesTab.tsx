import React, { useState, useEffect } from 'react';
import {
  Shield,
  Plus,
  Trash2,
  CheckCircle,
  XCircle,
  Eye,
  EyeOff,
  RefreshCw,
  AlertTriangle,
} from 'lucide-react';
import { apiFetch } from '../../lib/api.js';
import { AuthProfile, AuthType } from '../../types.js';

interface NewProfileForm {
  name: string;
  type: AuthType;
  headerName: string;
  headerValue: string;
  username: string;
  password: string;
  loginUrl: string;
  loginUsernameField: string;
  loginPasswordField: string;
  loginUsername: string;
  loginPassword: string;
}

interface TestState {
  testUrl: string;
  loading: boolean;
  result: { success: boolean; status?: number; message: string } | null;
}

const defaultForm: NewProfileForm = {
  name: '',
  type: 'bearer',
  headerName: '',
  headerValue: '',
  username: '',
  password: '',
  loginUrl: '',
  loginUsernameField: 'username',
  loginPasswordField: 'password',
  loginUsername: '',
  loginPassword: '',
};

export default function AuthProfilesTab() {
  const [profiles, setProfiles] = useState<AuthProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const [showCreateForm, setShowCreateForm] = useState(false);
  const [form, setForm] = useState<NewProfileForm>(defaultForm);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [testStates, setTestStates] = useState<Record<string, TestState>>({});

  const fetchProfiles = async () => {
    setLoading(true);
    setFetchError(null);
    try {
      const res = await apiFetch('/api/auth-profiles');
      if (res.ok) {
        const data = await res.json();
        setProfiles(data.profiles || data || []);
      } else {
        const data = await res.json();
        setFetchError(data.error || 'Failed to load auth profiles.');
      }
    } catch (err: any) {
      setFetchError(err.message || 'Network error.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProfiles();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      setCreateError('Profile name is required.');
      return;
    }
    setCreating(true);
    setCreateError(null);
    try {
      const body: Record<string, string> = { name: form.name.trim(), type: form.type };
      if (form.type === 'bearer' || form.type === 'cookie') {
        body.headerValue = form.headerValue;
      } else if (form.type === 'header') {
        body.headerName = form.headerName;
        body.headerValue = form.headerValue;
      } else if (form.type === 'basic') {
        body.username = form.username;
        body.password = form.password;
      } else if (form.type === 'form') {
        body.loginUrl = form.loginUrl;
        body.loginUsernameField = form.loginUsernameField || 'username';
        body.loginPasswordField = form.loginPasswordField || 'password';
        body.loginUsername = form.loginUsername;
        body.loginPassword = form.loginPassword;
      }

      const res = await apiFetch('/api/auth-profiles', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok) {
        setForm(defaultForm);
        setShowCreateForm(false);
        await fetchProfiles();
      } else {
        setCreateError(data.error || 'Failed to create profile.');
      }
    } catch (err: any) {
      setCreateError(err.message || 'Network error.');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (profileId: string) => {
    setDeletingId(profileId);
    try {
      const res = await apiFetch(`/api/auth-profiles/${profileId}`, { method: 'DELETE' });
      if (res.ok) {
        setProfiles(prev => prev.filter(p => p.id !== profileId));
      }
    } catch (err) {
      console.error('Failed to delete auth profile:', err);
    } finally {
      setDeletingId(null);
    }
  };

  const handleTest = async (profileId: string) => {
    const state = testStates[profileId];
    const testUrl = state?.testUrl || '';
    if (!testUrl.trim()) return;

    setTestStates(prev => ({
      ...prev,
      [profileId]: { ...prev[profileId], loading: true, result: null },
    }));
    try {
      const res = await apiFetch(`/api/auth-profiles/${profileId}/test`, {
        method: 'POST',
        body: JSON.stringify({ testUrl: testUrl.trim() }),
      });
      const data = await res.json();
      setTestStates(prev => ({
        ...prev,
        [profileId]: {
          ...prev[profileId],
          loading: false,
          result: {
            success: data.success ?? res.ok,
            status: data.status,
            message: data.message || (res.ok ? 'Authentication verified.' : 'Test failed.'),
          },
        },
      }));
    } catch (err: any) {
      setTestStates(prev => ({
        ...prev,
        [profileId]: {
          ...prev[profileId],
          loading: false,
          result: { success: false, message: err.message || 'Network error.' },
        },
      }));
    }
  };

  const toggleShowPassword = (key: string) => {
    setShowPasswords(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const setTestUrl = (profileId: string, url: string) => {
    setTestStates(prev => ({
      ...prev,
      [profileId]: { testUrl: url, loading: false, result: prev[profileId]?.result ?? null },
    }));
  };

  const authTypeLabel = (type: AuthType): string => {
    switch (type) {
      case 'bearer': return 'Bearer Token';
      case 'cookie': return 'Cookie';
      case 'header': return 'Custom Header';
      case 'basic': return 'HTTP Basic';
      case 'form': return 'Form Login';
    }
  };

  const inputClass =
    'bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono p-2 rounded w-full focus:outline-none transition-colors placeholder-[#52525b]';

  const labelClass = 'text-[10px] font-mono uppercase tracking-wider text-[#52525b] block mb-1';

  return (
    <div className="space-y-6 text-xs font-mono">
      {/* Info banner */}
      <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
        <Shield className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5 animate-pulse" />
        <div className="space-y-1">
          <h4 className="text-white text-xs uppercase font-bold">Credential Profiles for Authenticated Scans</h4>
          <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
            Store named credential sets to run authenticated black-box scans. Profiles are encrypted at rest and never
            exposed in scan results. Supported auth methods: Bearer token, Cookie passthrough, Custom header,
            HTTP Basic Auth, and Form-based auto-login.
          </p>
        </div>
      </div>

      {/* Header row */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-white uppercase tracking-tight">Auth Profiles</h3>
        <button
          onClick={() => { setShowCreateForm(!showCreateForm); setCreateError(null); }}
          className="px-4 py-2 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded transition-all flex items-center space-x-1.5 cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Profile</span>
        </button>
      </div>

      {/* Create form */}
      {showCreateForm && (
        <form
          onSubmit={handleCreate}
          className="bg-black/40 border border-[#27272a] rounded p-6 space-y-4"
        >
          <h4 className="text-white font-bold uppercase tracking-tight text-xs mb-2">New Auth Profile</h4>

          {/* Name + Type row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className={labelClass}>Profile Name</label>
              <input
                type="text"
                className={inputClass}
                placeholder="e.g. Staging Admin"
                value={form.name}
                onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))}
              />
            </div>
            <div>
              <label className={labelClass}>Auth Type</label>
              <select
                className={inputClass}
                value={form.type}
                onChange={e => setForm(prev => ({ ...prev, type: e.target.value as AuthType }))}
              >
                <option value="bearer">Bearer Token</option>
                <option value="cookie">Cookie</option>
                <option value="header">Custom Header</option>
                <option value="basic">HTTP Basic Auth</option>
                <option value="form">Form-based Login</option>
              </select>
            </div>
          </div>

          {/* Type-specific fields */}
          {(form.type === 'bearer' || form.type === 'cookie') && (
            <div>
              <label className={labelClass}>
                {form.type === 'bearer' ? 'Bearer Token' : 'Cookie String'}
              </label>
              <div className="relative">
                <input
                  type={showPasswords['new-headerValue'] ? 'text' : 'password'}
                  className={inputClass + ' pr-9'}
                  placeholder={
                    form.type === 'bearer'
                      ? 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                      : 'session=abc123; auth=xyz'
                  }
                  value={form.headerValue}
                  onChange={e => setForm(prev => ({ ...prev, headerValue: e.target.value }))}
                />
                <button
                  type="button"
                  onClick={() => toggleShowPassword('new-headerValue')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
                >
                  {showPasswords['new-headerValue'] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
          )}

          {form.type === 'header' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className={labelClass}>Header Name</label>
                <input
                  type="text"
                  className={inputClass}
                  placeholder="X-Api-Key"
                  value={form.headerName}
                  onChange={e => setForm(prev => ({ ...prev, headerName: e.target.value }))}
                />
              </div>
              <div>
                <label className={labelClass}>Header Value</label>
                <div className="relative">
                  <input
                    type={showPasswords['new-headerValue'] ? 'text' : 'password'}
                    className={inputClass + ' pr-9'}
                    placeholder="secret-api-key-value"
                    value={form.headerValue}
                    onChange={e => setForm(prev => ({ ...prev, headerValue: e.target.value }))}
                  />
                  <button
                    type="button"
                    onClick={() => toggleShowPassword('new-headerValue')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
                  >
                    {showPasswords['new-headerValue'] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
          )}

          {form.type === 'basic' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className={labelClass}>Username</label>
                <input
                  type="text"
                  className={inputClass}
                  placeholder="admin"
                  value={form.username}
                  onChange={e => setForm(prev => ({ ...prev, username: e.target.value }))}
                />
              </div>
              <div>
                <label className={labelClass}>Password</label>
                <div className="relative">
                  <input
                    type={showPasswords['new-password'] ? 'text' : 'password'}
                    className={inputClass + ' pr-9'}
                    placeholder="••••••••"
                    value={form.password}
                    onChange={e => setForm(prev => ({ ...prev, password: e.target.value }))}
                  />
                  <button
                    type="button"
                    onClick={() => toggleShowPassword('new-password')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
                  >
                    {showPasswords['new-password'] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
          )}

          {form.type === 'form' && (
            <div className="space-y-4">
              <div>
                <label className={labelClass}>Login URL</label>
                <input
                  type="text"
                  className={inputClass}
                  placeholder="https://app.example.com/login"
                  value={form.loginUrl}
                  onChange={e => setForm(prev => ({ ...prev, loginUrl: e.target.value }))}
                />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className={labelClass}>Username Field Name</label>
                  <input
                    type="text"
                    className={inputClass}
                    placeholder="username"
                    value={form.loginUsernameField}
                    onChange={e => setForm(prev => ({ ...prev, loginUsernameField: e.target.value }))}
                  />
                </div>
                <div>
                  <label className={labelClass}>Password Field Name</label>
                  <input
                    type="text"
                    className={inputClass}
                    placeholder="password"
                    value={form.loginPasswordField}
                    onChange={e => setForm(prev => ({ ...prev, loginPasswordField: e.target.value }))}
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className={labelClass}>Login Username</label>
                  <input
                    type="text"
                    className={inputClass}
                    placeholder="admin@example.com"
                    value={form.loginUsername}
                    onChange={e => setForm(prev => ({ ...prev, loginUsername: e.target.value }))}
                  />
                </div>
                <div>
                  <label className={labelClass}>Login Password</label>
                  <div className="relative">
                    <input
                      type={showPasswords['new-loginPassword'] ? 'text' : 'password'}
                      className={inputClass + ' pr-9'}
                      placeholder="••••••••"
                      value={form.loginPassword}
                      onChange={e => setForm(prev => ({ ...prev, loginPassword: e.target.value }))}
                    />
                    <button
                      type="button"
                      onClick={() => toggleShowPassword('new-loginPassword')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
                    >
                      {showPasswords['new-loginPassword'] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {createError && (
            <div className="flex items-center gap-2 text-[#f87171] bg-[#f87171]/5 border border-[#f87171]/20 rounded p-3 text-[11px]">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {createError}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-1">
            <button
              type="button"
              onClick={() => { setShowCreateForm(false); setForm(defaultForm); setCreateError(null); }}
              className="px-4 py-2 border border-[#27272a] text-[#a1a1aa] hover:text-white hover:border-[#3f3f46] text-xs font-mono uppercase tracking-wider rounded transition-all cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creating}
              className="px-4 py-2 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center space-x-1.5 cursor-pointer"
            >
              {creating ? (
                <><RefreshCw className="w-3.5 h-3.5 animate-spin" /><span>Saving...</span></>
              ) : (
                <><Plus className="w-3.5 h-3.5" /><span>Save Profile</span></>
              )}
            </button>
          </div>
        </form>
      )}

      {/* Fetch error */}
      {fetchError && (
        <div className="flex items-center gap-2 text-[#f87171] bg-[#f87171]/5 border border-[#f87171]/20 rounded p-3 text-[11px]">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {fetchError}
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="flex items-center justify-center py-16 text-[#52525b]">
          <RefreshCw className="w-5 h-5 animate-spin mr-2" />
          <span className="text-xs uppercase tracking-wider">Loading profiles...</span>
        </div>
      )}

      {/* Empty state */}
      {!loading && !fetchError && profiles.length === 0 && (
        <div className="text-center py-16 bg-black rounded border border-dashed border-[#27272a] flex flex-col items-center">
          <Shield className="w-10 h-10 text-zinc-600 mb-3" />
          <span className="text-xs text-white uppercase font-bold font-mono">No Auth Profiles Yet</span>
          <p className="text-[11px] text-[#52525b] mt-1.5 font-mono max-w-sm">
            Create a credential profile to enable authenticated scanning. Profiles are securely stored and reusable across multiple scans.
          </p>
        </div>
      )}

      {/* Profile list */}
      {!loading && profiles.length > 0 && (
        <div className="space-y-4">
          {profiles.map((profile) => {
            const testState = testStates[profile.id] ?? { testUrl: '', loading: false, result: null };
            return (
              <div
                key={profile.id}
                className="bg-black/80 border border-[#27272a] rounded p-5 space-y-4 hover:border-[#3f3f46] transition-colors"
              >
                {/* Profile header */}
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-white font-bold text-xs">{profile.name}</span>
                      <span className="text-[9px] font-mono uppercase bg-[#18181b] border border-[#27272a] text-[#22c55e] px-2 py-0.5 rounded">
                        {authTypeLabel(profile.type)}
                      </span>
                      {profile.verifiedAt && (
                        <span className="flex items-center gap-1 text-[9px] text-[#22c55e]">
                          <CheckCircle className="w-3 h-3" />
                          Verified {new Date(profile.verifiedAt).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                    <p className="text-[#52525b] text-[10px]">
                      Created {new Date(profile.createdAt).toLocaleString()} &bull; ID: {profile.id}
                    </p>
                  </div>
                  <button
                    onClick={() => handleDelete(profile.id)}
                    disabled={deletingId === profile.id}
                    className="shrink-0 px-3 py-1.5 border border-[#f87171]/30 text-[#f87171] hover:bg-[#f87171]/10 rounded text-[10px] font-mono uppercase tracking-wider transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer flex items-center gap-1.5"
                  >
                    {deletingId === profile.id ? (
                      <><RefreshCw className="w-3 h-3 animate-spin" /><span>Deleting...</span></>
                    ) : (
                      <><Trash2 className="w-3 h-3" /><span>Delete</span></>
                    )}
                  </button>
                </div>

                {/* Profile field summary */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 bg-[#0c0c0e] border border-[#27272a] rounded p-3">
                  {profile.type === 'bearer' && (
                    <div>
                      <span className={labelClass}>Token</span>
                      <span className="text-[#a1a1aa] text-[11px]">
                        {showPasswords[profile.id + '-val']
                          ? profile.headerValue || '(empty)'
                          : '••••••••••••••••'}
                        <button
                          type="button"
                          onClick={() => toggleShowPassword(profile.id + '-val')}
                          className="ml-2 text-[#52525b] hover:text-[#a1a1aa] cursor-pointer"
                        >
                          {showPasswords[profile.id + '-val'] ? <EyeOff className="w-3 h-3 inline" /> : <Eye className="w-3 h-3 inline" />}
                        </button>
                      </span>
                    </div>
                  )}
                  {profile.type === 'cookie' && (
                    <div>
                      <span className={labelClass}>Cookie</span>
                      <span className="text-[#a1a1aa] text-[11px]">
                        {showPasswords[profile.id + '-val']
                          ? profile.headerValue || '(empty)'
                          : '••••••••••••••••'}
                        <button
                          type="button"
                          onClick={() => toggleShowPassword(profile.id + '-val')}
                          className="ml-2 text-[#52525b] hover:text-[#a1a1aa] cursor-pointer"
                        >
                          {showPasswords[profile.id + '-val'] ? <EyeOff className="w-3 h-3 inline" /> : <Eye className="w-3 h-3 inline" />}
                        </button>
                      </span>
                    </div>
                  )}
                  {profile.type === 'header' && (
                    <>
                      <div>
                        <span className={labelClass}>Header Name</span>
                        <span className="text-[#a1a1aa] text-[11px]">{profile.headerName || '—'}</span>
                      </div>
                      <div>
                        <span className={labelClass}>Header Value</span>
                        <span className="text-[#a1a1aa] text-[11px]">
                          {showPasswords[profile.id + '-val']
                            ? profile.headerValue || '(empty)'
                            : '••••••••••••••••'}
                          <button
                            type="button"
                            onClick={() => toggleShowPassword(profile.id + '-val')}
                            className="ml-2 text-[#52525b] hover:text-[#a1a1aa] cursor-pointer"
                          >
                            {showPasswords[profile.id + '-val'] ? <EyeOff className="w-3 h-3 inline" /> : <Eye className="w-3 h-3 inline" />}
                          </button>
                        </span>
                      </div>
                    </>
                  )}
                  {profile.type === 'basic' && (
                    <>
                      <div>
                        <span className={labelClass}>Username</span>
                        <span className="text-[#a1a1aa] text-[11px]">{profile.username || '—'}</span>
                      </div>
                      <div>
                        <span className={labelClass}>Password</span>
                        <span className="text-[#a1a1aa] text-[11px]">
                          {showPasswords[profile.id + '-pass']
                            ? profile.password || '(empty)'
                            : '••••••••'}
                          <button
                            type="button"
                            onClick={() => toggleShowPassword(profile.id + '-pass')}
                            className="ml-2 text-[#52525b] hover:text-[#a1a1aa] cursor-pointer"
                          >
                            {showPasswords[profile.id + '-pass'] ? <EyeOff className="w-3 h-3 inline" /> : <Eye className="w-3 h-3 inline" />}
                          </button>
                        </span>
                      </div>
                    </>
                  )}
                  {profile.type === 'form' && (
                    <>
                      <div>
                        <span className={labelClass}>Login URL</span>
                        <span className="text-[#a1a1aa] text-[11px]">{profile.loginUrl || '—'}</span>
                      </div>
                      <div>
                        <span className={labelClass}>Username Field</span>
                        <span className="text-[#a1a1aa] text-[11px]">{profile.loginUsernameField || 'username'}</span>
                      </div>
                      <div>
                        <span className={labelClass}>Login Username</span>
                        <span className="text-[#a1a1aa] text-[11px]">{profile.loginUsername || '—'}</span>
                      </div>
                      <div>
                        <span className={labelClass}>Login Password</span>
                        <span className="text-[#a1a1aa] text-[11px]">
                          {showPasswords[profile.id + '-pass']
                            ? profile.loginPassword || '(empty)'
                            : '••••••••'}
                          <button
                            type="button"
                            onClick={() => toggleShowPassword(profile.id + '-pass')}
                            className="ml-2 text-[#52525b] hover:text-[#a1a1aa] cursor-pointer"
                          >
                            {showPasswords[profile.id + '-pass'] ? <EyeOff className="w-3 h-3 inline" /> : <Eye className="w-3 h-3 inline" />}
                          </button>
                        </span>
                      </div>
                    </>
                  )}
                </div>

                {/* Inline test form */}
                <div className="space-y-2">
                  <label className={labelClass}>Test Credentials</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono p-2 rounded flex-1 focus:outline-none transition-colors placeholder-[#52525b]"
                      placeholder="https://app.example.com/api/me"
                      value={testState.testUrl}
                      onChange={e => setTestUrl(profile.id, e.target.value)}
                    />
                    <button
                      type="button"
                      onClick={() => handleTest(profile.id)}
                      disabled={testState.loading || !testState.testUrl.trim()}
                      className="px-4 py-2 border border-[#27272a] hover:border-[#22c55e] text-[#a1a1aa] hover:text-[#22c55e] text-xs font-mono uppercase tracking-wider rounded transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer flex items-center gap-1.5 shrink-0"
                    >
                      {testState.loading ? (
                        <><RefreshCw className="w-3 h-3 animate-spin" /><span>Testing...</span></>
                      ) : (
                        <span>Test</span>
                      )}
                    </button>
                  </div>
                  {testState.result && (
                    <div
                      className={`flex items-start gap-2 rounded p-3 text-[11px] ${
                        testState.result.success
                          ? 'bg-[#22c55e]/5 border border-[#22c55e]/20 text-[#22c55e]'
                          : 'bg-[#f87171]/5 border border-[#f87171]/20 text-[#f87171]'
                      }`}
                    >
                      {testState.result.success ? (
                        <CheckCircle className="w-4 h-4 shrink-0 mt-0.5" />
                      ) : (
                        <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
                      )}
                      <div>
                        {testState.result.status !== undefined && (
                          <span className="font-bold mr-2">HTTP {testState.result.status}</span>
                        )}
                        {testState.result.message}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
