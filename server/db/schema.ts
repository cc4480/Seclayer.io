import Database from 'better-sqlite3';

// Creates the schema (idempotently) and applies additive column migrations.
// Called once from the SqliteDb constructor.
export function runMigrations(db: Database.Database): void {
  db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0,
        apiKey TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        url TEXT NOT NULL,
        authHeader TEXT,
        status TEXT NOT NULL,
        score INTEGER,
        severity TEXT,
        findings TEXT,
        aiSummary TEXT,
        error TEXT,
        createdAt TEXT NOT NULL,
        completedAt TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(userId);
      CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        amount INTEGER NOT NULL,
        type TEXT NOT NULL,
        stripeSessionId TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(userId);
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        key TEXT UNIQUE NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_keys_user ON api_keys(userId);
      CREATE TABLE IF NOT EXISTS suppressions (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        targetUrl TEXT NOT NULL,
        findingTitle TEXT NOT NULL,
        reason TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_supp_user ON suppressions(userId);
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
      CREATE INDEX IF NOT EXISTS idx_mon_user ON monitored_targets(userId);
      CREATE TABLE IF NOT EXISTS login_tokens (
        tokenHash TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        expiresAt TEXT NOT NULL,
        consumedAt TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        tokenHash TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        expiresAt TEXT NOT NULL,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(userId);
    `);
  // Additive column migrations (safe across existing databases).
  addColumnIfMissing(db, "users", "notifyWebhook", "TEXT");
}

function addColumnIfMissing(db: Database.Database, table: string, column: string, decl: string): void {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
  }
}
