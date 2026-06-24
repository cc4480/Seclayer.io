import Database from 'better-sqlite3';

export function runMigrations(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      credits INTEGER NOT NULL DEFAULT 0,
      apiKey TEXT,
      passwordHash TEXT,
      createdAt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      amount INTEGER NOT NULL,
      type TEXT NOT NULL,
      stripeSessionId TEXT,
      createdAt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS api_keys (
      key TEXT PRIMARY KEY,
      id TEXT NOT NULL,
      userId TEXT NOT NULL,
      credits INTEGER NOT NULL DEFAULT 0,
      active INTEGER NOT NULL DEFAULT 1,
      createdAt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      url TEXT NOT NULL,
      authHeader TEXT,
      authProfileId TEXT,
      webhookUrl TEXT,
      status TEXT NOT NULL,
      score INTEGER,
      severity TEXT,
      findings TEXT,
      aiSummary TEXT,
      diagnostics TEXT,
      crawl TEXT,
      error TEXT,
      createdAt TEXT NOT NULL,
      completedAt TEXT
    );
    CREATE TABLE IF NOT EXISTS suppressions (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      targetUrl TEXT NOT NULL,
      findingTitle TEXT NOT NULL,
      reason TEXT,
      createdAt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS monitored_targets (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      url TEXT NOT NULL,
      frequencyDays INTEGER NOT NULL,
      scheduleString TEXT,
      lastScannedAt TEXT,
      nextScanAt TEXT,
      createdAt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_profiles (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      data TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS github_connections (
      userId TEXT PRIMARY KEY,
      repoFullName TEXT NOT NULL,
      token TEXT NOT NULL,
      createdAt TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_scans_userId ON scans(userId);
    CREATE INDEX IF NOT EXISTS idx_tx_userId ON transactions(userId);
    CREATE INDEX IF NOT EXISTS idx_keys_userId ON api_keys(userId);
    CREATE INDEX IF NOT EXISTS idx_supp_userId ON suppressions(userId);
    CREATE INDEX IF NOT EXISTS idx_mon_userId ON monitored_targets(userId);
    CREATE INDEX IF NOT EXISTS idx_ap_userId ON auth_profiles(userId);
  `);
}
