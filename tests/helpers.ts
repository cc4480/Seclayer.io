import { LocalFileDb } from '../server/db.js';
import { hashPassword, signToken } from '../server/auth.js';
import { createApp } from '../server.js';
import type { Express } from 'express';

export function makeTempDb(): { db: LocalFileDb; cleanup: () => void } {
  // Each test gets an isolated in-memory SQLite database — no file to clean up.
  const db = new LocalFileDb(':memory:');
  return {
    db,
    cleanup: () => { /* in-memory DB is discarded when GC'd */ },
  };
}

export interface TestContext {
  app: Express;
  db: LocalFileDb;
  cleanup: () => void;
}

export function makeTestApp(): TestContext {
  const { db, cleanup } = makeTempDb();
  const app = createApp(db);
  return { app, db, cleanup };
}

export function registerAndLogin(db: LocalFileDb, email = 'test@example.com', password = 'password123') {
  const user = db.registerUser(email, hashPassword(password));
  const token = signToken(user.id);
  return { user, token };
}
