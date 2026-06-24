import React from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { AuthProfile } from '../../../types.js';
import { labelClass } from './styles.js';

interface ProfileFieldSummaryProps {
  profile: AuthProfile;
  showPasswords: Record<string, boolean>;
  onTogglePassword: (key: string) => void;
}

export default function ProfileFieldSummary({ profile, showPasswords, onTogglePassword }: ProfileFieldSummaryProps) {
  return (
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
              onClick={() => onTogglePassword(profile.id + '-val')}
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
              onClick={() => onTogglePassword(profile.id + '-val')}
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
                onClick={() => onTogglePassword(profile.id + '-val')}
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
                onClick={() => onTogglePassword(profile.id + '-pass')}
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
                onClick={() => onTogglePassword(profile.id + '-pass')}
                className="ml-2 text-[#52525b] hover:text-[#a1a1aa] cursor-pointer"
              >
                {showPasswords[profile.id + '-pass'] ? <EyeOff className="w-3 h-3 inline" /> : <Eye className="w-3 h-3 inline" />}
              </button>
            </span>
          </div>
        </>
      )}
    </div>
  );
}
