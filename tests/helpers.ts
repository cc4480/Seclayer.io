import fs from 'fs';
import os from 'os';
import path from 'path';
import { LocalFileDb } from '../server/db.js';
import { hashPassword, signToken } from '../server/auth.js';
import { createApp } from '../server.js';
import type { Express } from 'express';

export function makeTempDb(): { db: LocalFileDb; cleanup: () => void } {
  const tmpFile = path.join(os.tmpdir(), `sl-test-${Math.random().toString(36).slice(2)}.json`);
  const db = new LocalFileDb(tmpFile);
  return {
    db,
    cleanup: () => {
      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    },
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
