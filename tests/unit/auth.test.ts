import { describe, it, expect } from 'vitest';
import { hashPassword, verifyPassword, signToken, verifyToken } from '../../server/auth.js';

describe('hashPassword / verifyPassword', () => {
  it('produces a bcrypt hash distinct from the input', () => {
    const hash = hashPassword('mysecret99');
    expect(hash).not.toBe('mysecret99');
    expect(hash).toMatch(/^\$2[aby]?\$/);
  });

  it('verifies a correct password', () => {
    const hash = hashPassword('correct-horse-battery');
    expect(verifyPassword('correct-horse-battery', hash)).toBe(true);
  });

  it('rejects an incorrect password', () => {
    const hash = hashPassword('rightpassword');
    expect(verifyPassword('wrongpassword', hash)).toBe(false);
  });

  it('produces unique hashes for the same input (different salts)', () => {
    const a = hashPassword('same');
    const b = hashPassword('same');
    expect(a).not.toBe(b);
    expect(verifyPassword('same', a)).toBe(true);
    expect(verifyPassword('same', b)).toBe(true);
  });
});

describe('signToken / verifyToken', () => {
  it('signs a token that verifyToken can decode', () => {
    const token = signToken('user_abc123');
    const payload = verifyToken(token);
    expect(payload).not.toBeNull();
    expect(payload!.userId).toBe('user_abc123');
  });

  it('returns null for a random string', () => {
    expect(verifyToken('not-a-jwt')).toBeNull();
  });

  it('returns null for a token with a tampered signature', () => {
    const token = signToken('user_xyz');
    const [header, body] = token.split('.');
    const tampered = `${header}.${body}.invalidsignature`;
    expect(verifyToken(tampered)).toBeNull();
  });

  it('returns null for an empty string', () => {
    expect(verifyToken('')).toBeNull();
  });
});
