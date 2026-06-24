import React, { useState, useEffect } from 'react';
import { apiFetch } from '../../../lib/api.js';
import { AuthProfile, AuthType } from '../../../types.js';
import { NewProfileForm, TestState, defaultForm } from './types.js';

export function useAuthProfiles() {
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

  return {
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
  };
}
