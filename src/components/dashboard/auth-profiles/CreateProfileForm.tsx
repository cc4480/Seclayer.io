import React from 'react';
import { Plus, RefreshCw, AlertTriangle } from 'lucide-react';
import { AuthType } from '../../../types.js';
import { NewProfileForm, defaultForm } from './types.js';
import { inputClass, labelClass } from './styles.js';
import {
  BearerOrCookieFields,
  HeaderFields,
  BasicAuthFields,
  FormLoginFields,
} from './CreateProfileFormFields.js';

interface CreateProfileFormProps {
  form: NewProfileForm;
  setForm: React.Dispatch<React.SetStateAction<NewProfileForm>>;
  creating: boolean;
  createError: string | null;
  showPasswords: Record<string, boolean>;
  onTogglePassword: (key: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  onCancel: () => void;
}

export default function CreateProfileForm({
  form,
  setForm,
  creating,
  createError,
  showPasswords,
  onTogglePassword,
  onSubmit,
  onCancel,
}: CreateProfileFormProps) {
  return (
    <form
      onSubmit={onSubmit}
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
        <BearerOrCookieFields
          form={form}
          setForm={setForm}
          showPasswords={showPasswords}
          onTogglePassword={onTogglePassword}
        />
      )}

      {form.type === 'header' && (
        <HeaderFields
          form={form}
          setForm={setForm}
          showPasswords={showPasswords}
          onTogglePassword={onTogglePassword}
        />
      )}

      {form.type === 'basic' && (
        <BasicAuthFields
          form={form}
          setForm={setForm}
          showPasswords={showPasswords}
          onTogglePassword={onTogglePassword}
        />
      )}

      {form.type === 'form' && (
        <FormLoginFields
          form={form}
          setForm={setForm}
          showPasswords={showPasswords}
          onTogglePassword={onTogglePassword}
        />
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
          onClick={() => { onCancel(); setForm(defaultForm); }}
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
  );
}
