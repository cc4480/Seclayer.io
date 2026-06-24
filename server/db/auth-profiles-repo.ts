import crypto from 'crypto';
import Database from 'better-sqlite3';
import { AuthProfile } from '../../src/types.js';

export class AuthProfilesRepo {
  constructor(private db: Database.Database) {}

  createAuthProfile(userId: string, data: Omit<AuthProfile, 'id' | 'userId' | 'createdAt'>): AuthProfile {
    const id = 'ap_' + crypto.randomBytes(8).toString('hex');
    const profile: AuthProfile = { ...data, id, userId, createdAt: new Date().toISOString() };
    this.db.prepare('INSERT INTO auth_profiles (id, userId, data) VALUES (?, ?, ?)')
      .run(id, userId, JSON.stringify(profile));
    return profile;
  }

  getAuthProfile(userId: string, id: string): AuthProfile | null {
    const row = this.db.prepare('SELECT data FROM auth_profiles WHERE id = ? AND userId = ?').get(id, userId) as any;
    return row ? (JSON.parse(row.data) as AuthProfile) : null;
  }

  listAuthProfiles(userId: string): AuthProfile[] {
    return this.db.prepare('SELECT data FROM auth_profiles WHERE userId = ?')
      .all(userId).map((r: any) => JSON.parse(r.data) as AuthProfile);
  }

  deleteAuthProfile(userId: string, id: string): boolean {
    const info = this.db.prepare('DELETE FROM auth_profiles WHERE id = ? AND userId = ?').run(id, userId);
    return info.changes > 0;
  }

  updateAuthProfile(userId: string, id: string, updates: Partial<Omit<AuthProfile, 'id' | 'userId' | 'createdAt'>>): AuthProfile | null {
    const existing = this.getAuthProfile(userId, id);
    if (!existing) return null;
    const merged = { ...existing, ...updates };
    this.db.prepare('UPDATE auth_profiles SET data = ? WHERE id = ? AND userId = ?')
      .run(JSON.stringify(merged), id, userId);
    return merged;
  }
}
