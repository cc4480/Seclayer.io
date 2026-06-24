import React from 'react';
import { Trash2, CheckCircle, XCircle, RefreshCw } from 'lucide-react';
import { AuthProfile, AuthType } from '../../../types.js';
import { TestState } from './types.js';
import { labelClass } from './styles.js';
import ProfileFieldSummary from './ProfileFieldSummary.js';

interface ProfileCardProps {
  key?: string;
  profile: AuthProfile;
  testState: TestState;
  deletingId: string | null;
  showPasswords: Record<string, boolean>;
  authTypeLabel: (type: AuthType) => string;
  onDelete: (profileId: string) => void;
  onTest: (profileId: string) => void;
  onTogglePassword: (key: string) => void;
  onSetTestUrl: (profileId: string, url: string) => void;
}

export default function ProfileCard({
  profile,
  testState,
  deletingId,
  showPasswords,
  authTypeLabel,
  onDelete,
  onTest,
  onTogglePassword,
  onSetTestUrl,
}: ProfileCardProps) {
  return (
    <div className="bg-black/80 border border-[#27272a] rounded p-5 space-y-4 hover:border-[#3f3f46] transition-colors">
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
          onClick={() => onDelete(profile.id)}
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
      <ProfileFieldSummary
        profile={profile}
        showPasswords={showPasswords}
        onTogglePassword={onTogglePassword}
      />

      {/* Inline test form */}
      <div className="space-y-2">
        <label className={labelClass}>Test Credentials</label>
        <div className="flex gap-2">
          <input
            type="text"
            className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono p-2 rounded flex-1 focus:outline-none transition-colors placeholder-[#52525b]"
            placeholder="https://app.example.com/api/me"
            value={testState.testUrl}
            onChange={e => onSetTestUrl(profile.id, e.target.value)}
          />
          <button
            type="button"
            onClick={() => onTest(profile.id)}
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
}
