import { describe, it, expect } from 'vitest';
import {
  createOastToken,
  recordInteraction,
  hasInteraction,
  getInteractions,
  waitForInteraction,
} from '../../server/oast.js';

describe('createOastToken', () => {
  it('returns a 28-character hex string', () => {
    const token = createOastToken();
    expect(token).toMatch(/^[0-9a-f]{28}$/);
  });

  it('generates unique tokens on repeated calls', () => {
    const tokens = new Set(Array.from({ length: 20 }, () => createOastToken()));
    expect(tokens.size).toBe(20);
  });

  it('initialises with no interactions', () => {
    const token = createOastToken();
    expect(hasInteraction(token)).toBe(false);
    expect(getInteractions(token)).toHaveLength(0);
  });
});

describe('recordInteraction / hasInteraction / getInteractions', () => {
  it('records an interaction for a known token', () => {
    const token = createOastToken();
    recordInteraction(token, '1.2.3.4', `/oast/${token}`, 'GET');

    expect(hasInteraction(token)).toBe(true);
    const list = getInteractions(token);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      token,
      sourceIp: '1.2.3.4',
      path: `/oast/${token}`,
      method: 'GET',
    });
    expect(typeof list[0].timestamp).toBe('number');
    expect(list[0].timestamp).toBeLessThanOrEqual(Date.now());
  });

  it('accumulates multiple interactions in order', () => {
    const token = createOastToken();
    recordInteraction(token, '10.0.0.1', '/oast/' + token, 'GET');
    recordInteraction(token, '10.0.0.2', '/oast/' + token, 'POST');

    const list = getInteractions(token);
    expect(list).toHaveLength(2);
    expect(list[0].method).toBe('GET');
    expect(list[1].method).toBe('POST');
  });

  it('silently ignores recordInteraction for an unknown token', () => {
    expect(() =>
      recordInteraction('deadbeef_not_a_real_token', '1.2.3.4', '/oast/x', 'GET')
    ).not.toThrow();
  });

  it('returns empty array for an unknown token', () => {
    expect(getInteractions('totally_unknown_token')).toHaveLength(0);
    expect(getInteractions('totally_unknown_token')).toHaveLength(0);
  });

  it('does not leak interactions between different tokens', () => {
    const tokenA = createOastToken();
    const tokenB = createOastToken();
    recordInteraction(tokenA, '1.2.3.4', '/oast/' + tokenA, 'GET');

    expect(hasInteraction(tokenB)).toBe(false);
    expect(getInteractions(tokenB)).toHaveLength(0);
  });

  it('hasInteraction returns false before any recording', () => {
    const token = createOastToken();
    expect(hasInteraction(token)).toBe(false);
  });
});

describe('waitForInteraction', () => {
  it('resolves true immediately when interaction already exists', async () => {
    const token = createOastToken();
    recordInteraction(token, '9.9.9.9', '/oast/' + token, 'GET');
    const result = await waitForInteraction(token, 2000);
    expect(result).toBe(true);
  });

  it('resolves true when interaction arrives during the polling window', async () => {
    const token = createOastToken();
    // Inject interaction at 150 ms; poll fires at 300 ms and catches it
    setTimeout(() => recordInteraction(token, '5.6.7.8', '/oast/' + token, 'POST'), 150);
    const result = await waitForInteraction(token, 1000);
    expect(result).toBe(true);
  });

  it('resolves false when timeout expires with no interaction', async () => {
    const token = createOastToken();
    // 400 ms timeout — two poll ticks at 300 ms, then resolves false
    const result = await waitForInteraction(token, 400);
    expect(result).toBe(false);
  }, 5000);
});
