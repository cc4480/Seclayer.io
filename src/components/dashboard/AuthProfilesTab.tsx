import React from 'react';
import { Shield, Plus, RefreshCw, AlertTriangle } from 'lucide-react';
import CreateProfileForm from './auth-profiles/CreateProfileForm.js';
import ProfileCard from './auth-profiles/ProfileCard.js';
import { useAuthProfiles } from './auth-profiles/useAuthProfiles.js';

export default function AuthProfilesTab() {
  const {
    profiles,
    loading,
    fetchError,
    showCreateForm,
    setShowCreateForm,
    form,
    setForm,
    creating,
    createError,
    setCreateError,
    showPasswords,
    deletingId,
    testStates,
    handleCreate,
    handleDelete,
    handleTest,
    toggleShowPassword,
    setTestUrl,
    authTypeLabel,
  } = useAuthProfiles();

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
        <CreateProfileForm
          form={form}
          setForm={setForm}
          creating={creating}
          createError={createError}
          showPasswords={showPasswords}
          onTogglePassword={toggleShowPassword}
          onSubmit={handleCreate}
          onCancel={() => { setShowCreateForm(false); setCreateError(null); }}
        />
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
              <ProfileCard
                key={profile.id}
                profile={profile}
                testState={testState}
                deletingId={deletingId}
                showPasswords={showPasswords}
                authTypeLabel={authTypeLabel}
                onDelete={handleDelete}
                onTest={handleTest}
                onTogglePassword={toggleShowPassword}
                onSetTestUrl={setTestUrl}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
