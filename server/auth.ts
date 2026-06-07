import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const DEV_SECRET = 'seclayer-dev-secret-change-in-production';
const JWT_SECRET = process.env.JWT_SECRET || DEV_SECRET;
const JWT_EXPIRES_IN = '7d';

if (process.env.NODE_ENV === 'production' && JWT_SECRET === DEV_SECRET) {
  throw new Error('JWT_SECRET must be set to a strong random value in production. Set the JWT_SECRET environment variable.');
}

export function hashPassword(password: string): string {
  return bcrypt.hashSync(password, 12);
}

export function verifyPassword(password: string, hash: string): boolean {
  return bcrypt.compareSync(password, hash);
}

export function signToken(userId: string): string {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

export function verifyToken(token: string): { userId: string } | null {
  try {
    return jwt.verify(token, JWT_SECRET) as { userId: string };
  } catch {
    return null;
  }
}
