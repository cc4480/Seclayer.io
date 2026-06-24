import path from 'path';
import Database from 'better-sqlite3';
import { User, Scan, CreditTransaction, ApiKey, Finding, SuppressionRule, MonitoredTarget, AuthProfile } from '../src/types.js';
import { runMigrations } from './db/schema.js';
import { cleanUrl, recalculateScore } from './db/score-helpers.js';
import { UsersRepo, DbUser } from './db/users-repo.js';
import { ScansRepo } from './db/scans-repo.js';
import { ApiKeysRepo } from './db/api-keys-repo.js';
import { SuppressionsRepo } from './db/suppressions-repo.js';
import { MonitoringRepo } from './db/monitoring-repo.js';
import { ScanLogsStore } from './db/scan-logs.js';
import { AuthProfilesRepo } from './db/auth-profiles-repo.js';
import { GithubConnectionsRepo } from './db/github-connections-repo.js';

export { cleanUrl, recalculateScore };
export type { DbUser };
const DEFAULT_DB_FILE = process.env.DB_PATH || path.join(process.cwd(), 'seclayer.db');
// SQLite-backed persistent store (better-sqlite3, synchronous). Class name kept as
// LocalFileDb for drop-in compatibility with existing imports + the test suite.
export class LocalFileDb {
  private db: Database.Database;
  private readonly scanLogs = new ScanLogsStore();
  private readonly users: UsersRepo;
  private readonly scans: ScansRepo;
  private readonly apiKeys: ApiKeysRepo;
  private readonly suppressions: SuppressionsRepo;
  private readonly monitoring: MonitoringRepo;
  private readonly authProfiles: AuthProfilesRepo;
  private readonly githubConnections: GithubConnectionsRepo;

  constructor(dbFilePath: string = DEFAULT_DB_FILE) {
    this.db = new Database(dbFilePath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    runMigrations(this.db);
    this.users = new UsersRepo(this.db);
    this.scans = new ScansRepo(this.db);
    this.apiKeys = new ApiKeysRepo(this.db, this.users);
    this.suppressions = new SuppressionsRepo(this.db, this.scans);
    this.monitoring = new MonitoringRepo(this.db);
    this.authProfiles = new AuthProfilesRepo(this.db);
    this.githubConnections = new GithubConnectionsRepo(this.db);
  }

  // --- Auth ---
  findUserByEmail(email: string): DbUser | null {
    return this.users.findUserByEmail(email);
  }

  registerUser(email: string, passwordHash: string): User {
    return this.users.registerUser(email, passwordHash);
  }

  // --- Users ---
  getUser(id: string): User | undefined {
    return this.users.getUser(id);
  }

  getDbUser(id: string): DbUser | undefined {
    return this.users.getDbUser(id);
  }

  addCredits(userId: string, amount: number, type: 'purchase' | 'scan_debit', stripeSessionId?: string): User {
    return this.users.addCredits(userId, amount, type, stripeSessionId);
  }

  deductCredits(userId: string, amount: number): boolean {
    return this.users.deductCredits(userId, amount);
  }

  getTransactions(userId: string): CreditTransaction[] {
    return this.users.getTransactions(userId);
  }

  // --- Scans ---
  listScans(userId: string): Scan[] {
    return this.scans.listScans(userId);
  }

  getScan(id: string): Scan | undefined {
    return this.scans.getScan(id);
  }

  createScan(userId: string, url: string, authHeader?: string): Scan {
    return this.scans.createScan(userId, url, authHeader);
  }

  updateScan(id: string, updates: Partial<Scan>): Scan {
    return this.scans.updateScan(id, updates);
  }

  // Patch a single finding inside a scan (remediation lifecycle updates).
  updateFinding(scanId: string, findingId: string, updates: Partial<Finding>): Scan | null {
    return this.scans.updateFinding(scanId, findingId, updates);
  }

  // --- API Keys ---
  listApiKeys(userId: string): ApiKey[] {
    return this.apiKeys.listApiKeys(userId);
  }

  findApiKey(keyStr: string): ApiKey | null {
    return this.apiKeys.findApiKey(keyStr);
  }

  generateApiKey(userId: string): ApiKey {
    return this.apiKeys.generateApiKey(userId);
  }

  revokeApiKey(userId: string, keyId: string): boolean {
    return this.apiKeys.revokeApiKey(userId, keyId);
  }

  validateApiKeyAndDeduct(apiKeyString: string, quantity: number = 1): User | null {
    return this.apiKeys.validateApiKeyAndDeduct(apiKeyString, quantity);
  }

  // --- Suppression Rules ---
  listSuppressions(userId: string): SuppressionRule[] {
    return this.suppressions.listSuppressions(userId);
  }

  addSuppression(userId: string, targetUrl: string, findingTitle: string, reason: string): SuppressionRule {
    return this.suppressions.addSuppression(userId, targetUrl, findingTitle, reason);
  }

  removeSuppression(userId: string, ruleId: string): boolean {
    return this.suppressions.removeSuppression(userId, ruleId);
  }

  // --- Monitored Targets ---
  listMonitoredTargets(userId: string): MonitoredTarget[] {
    return this.monitoring.listMonitoredTargets(userId);
  }

  addMonitoredTarget(userId: string, url: string, frequencyDays: number, scheduleString?: string): MonitoredTarget {
    return this.monitoring.addMonitoredTarget(userId, url, frequencyDays, scheduleString);
  }

  removeMonitoredTarget(userId: string, id: string): boolean {
    return this.monitoring.removeMonitoredTarget(userId, id);
  }

  getDueMonitoringTargets(): MonitoredTarget[] {
    return this.monitoring.getDueMonitoringTargets();
  }

  touchMonitoredTarget(id: string): void {
    this.monitoring.touchMonitoredTarget(id);
  }

  // --- Scan logs (transient, in-memory — only relevant during an active scan) ---
  appendScanLog(scanId: string, message: string): void {
    this.scanLogs.appendScanLog(scanId, message);
  }

  getScanLogs(scanId: string): string[] {
    return this.scanLogs.getScanLogs(scanId);
  }

  getScanWithSuppressedFindings(scan: Scan): Scan {
    return this.suppressions.getScanWithSuppressedFindings(scan);
  }

  // --- Auth Profiles ---
  createAuthProfile(userId: string, data: Omit<AuthProfile, 'id' | 'userId' | 'createdAt'>): AuthProfile {
    return this.authProfiles.createAuthProfile(userId, data);
  }

  getAuthProfile(userId: string, id: string): AuthProfile | null {
    return this.authProfiles.getAuthProfile(userId, id);
  }

  listAuthProfiles(userId: string): AuthProfile[] {
    return this.authProfiles.listAuthProfiles(userId);
  }

  deleteAuthProfile(userId: string, id: string): boolean {
    return this.authProfiles.deleteAuthProfile(userId, id);
  }

  updateAuthProfile(userId: string, id: string, updates: Partial<Omit<AuthProfile, 'id' | 'userId' | 'createdAt'>>): AuthProfile | null {
    return this.authProfiles.updateAuthProfile(userId, id, updates);
  }

  // --- GitHub connection (one per user — used for Auto-Fix PRs) ---
  setGithubConnection(userId: string, repoFullName: string, token: string): { repoFullName: string; createdAt: string } {
    return this.githubConnections.setGithubConnection(userId, repoFullName, token);
  }

  getGithubConnection(userId: string): { repoFullName: string; token: string; createdAt: string } | null {
    return this.githubConnections.getGithubConnection(userId);
  }

  removeGithubConnection(userId: string): boolean {
    return this.githubConnections.removeGithubConnection(userId);
  }
}

export const db = new LocalFileDb();
