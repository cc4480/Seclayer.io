import Database from 'better-sqlite3';

export class GithubConnectionsRepo {
  constructor(private db: Database.Database) {}

  setGithubConnection(userId: string, repoFullName: string, token: string): { repoFullName: string; createdAt: string } {
    const createdAt = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO github_connections (userId, repoFullName, token, createdAt) VALUES (?, ?, ?, ?)
      ON CONFLICT(userId) DO UPDATE SET repoFullName = excluded.repoFullName, token = excluded.token, createdAt = excluded.createdAt
    `).run(userId, repoFullName, token, createdAt);
    return { repoFullName, createdAt };
  }

  getGithubConnection(userId: string): { repoFullName: string; token: string; createdAt: string } | null {
    const row = this.db.prepare('SELECT * FROM github_connections WHERE userId = ?').get(userId) as any;
    return row ? { repoFullName: row.repoFullName, token: row.token, createdAt: row.createdAt } : null;
  }

  removeGithubConnection(userId: string): boolean {
    const info = this.db.prepare('DELETE FROM github_connections WHERE userId = ?').run(userId);
    return info.changes > 0;
  }
}
