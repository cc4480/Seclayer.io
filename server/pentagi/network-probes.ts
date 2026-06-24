import net from 'net';
import tls from 'tls';

export async function probePort(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (result: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

export async function getSslCertInfo(hostname: string): Promise<{ issuer: string; expires: string; daysLeft: number } | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        if (cert?.valid_to) {
          const expires = new Date(cert.valid_to);
          const daysLeft = Math.floor((expires.getTime() - Date.now()) / 86400000);
          resolve({
            issuer: (cert.issuer?.O as string) || (cert.issuer?.CN as string) || 'Unknown',
            expires: expires.toISOString().split('T')[0],
            daysLeft,
          });
        } else {
          resolve(null);
        }
      }
    );
    socket.once('error', () => resolve(null));
    socket.setTimeout(5000, () => { socket.destroy(); resolve(null); });
  });
}

export async function httpProbe(
  url: string,
  init: RequestInit = {},
  timeoutMs = 4000
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    clearTimeout(timer);
    const body = await res.text().catch(() => '');
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body, headers };
  } catch {
    return null;
  }
}

export async function httpProbeWithTiming(
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000
): Promise<{ status: number; body: string; headers: Record<string, string>; elapsedMs: number } | null> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const tStart = Date.now();
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    const elapsedMs = Date.now() - tStart;
    clearTimeout(timer);
    const body = await res.text().catch(() => '');
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body, headers, elapsedMs };
  } catch (e: any) {
    const elapsedMs = Date.now();
    // AbortError means we hit the timeout — record it as a timing data point
    if (e?.name === 'AbortError') return { status: 0, body: '', headers: {}, elapsedMs: timeoutMs };
    return null;
  }
}

// Test whether the server accepts a specific TLS protocol version
export async function testTlsVersion(hostname: string, version: 'TLSv1' | 'TLSv1.1'): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false,
        minVersion: version, maxVersion: version },
      () => { sock.destroy(); resolve(true); }
    );
    sock.once('error', () => resolve(false));
    sock.setTimeout(4000, () => { sock.destroy(); resolve(false); });
  });
}

// Attempt DNS zone transfer (AXFR) via raw TCP DNS query
export async function attemptAxfr(ns: string, zone: string): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let resolved = false;
    const done = (result: boolean) => {
      if (!resolved) { resolved = true; sock.destroy(); resolve(result); }
    };

    // Build DNS AXFR query
    const labels = zone.split('.').flatMap(part => {
      const b = Buffer.from(part, 'ascii');
      return [b.length, ...b];
    });
    const qName = Buffer.from([...labels, 0]);
    const header = Buffer.alloc(12);
    header.writeUInt16BE(0x1337, 0); // txid
    header.writeUInt16BE(0, 2);      // standard query, no flags
    header.writeUInt16BE(1, 4);      // QDCOUNT = 1
    const footer = Buffer.from([0, 252, 0, 1]); // QTYPE=AXFR(252), QCLASS=IN(1)
    const query = Buffer.concat([header, qName, footer]);
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(query.length, 0);
    const tcpMsg = Buffer.concat([lenBuf, query]);

    let totalBytes = 0;
    sock.setTimeout(4000);
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
    sock.on('data', (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > 200) done(true); // substantial response = zone data returned
    });
    sock.connect(53, ns, () => sock.write(tcpMsg));
    setTimeout(() => done(false), 5000);
  });
}
