import React from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { NewProfileForm } from './types.js';
import { inputClass, labelClass } from './styles.js';

interface FieldsProps {
  form: NewProfileForm;
  setForm: React.Dispatch<React.SetStateAction<NewProfileForm>>;
  showPasswords: Record<string, boolean>;
  onTogglePassword: (key: string) => void;
}

export function BearerOrCookieFields({ form, setForm, showPasswords, onTogglePassword }: FieldsProps) {
  return (
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
          onClick={() => onTogglePassword('new-headerValue')}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
        >
          {showPasswords['new-headerValue'] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
        </button>
      </div>
    </div>
  );
}

export function HeaderFields({ form, setForm, showPasswords, onTogglePassword }: FieldsProps) {
  return (
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
            onClick={() => onTogglePassword('new-headerValue')}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
          >
            {showPasswords['new-headerValue'] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>
    </div>
  );
}

export function BasicAuthFields({ form, setForm, showPasswords, onTogglePassword }: FieldsProps) {
  return (
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
            onClick={() => onTogglePassword('new-password')}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
          >
            {showPasswords['new-password'] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>
    </div>
  );
}

export function FormLoginFields({ form, setForm, showPasswords, onTogglePassword }: FieldsProps) {
  return (
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
              onClick={() => onTogglePassword('new-loginPassword')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[#52525b] hover:text-[#a1a1aa] transition-colors cursor-pointer"
            >
              {showPasswords['new-loginPassword'] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
