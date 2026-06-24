import crypto from 'crypto';
import type { CrawlForm } from '../../src/types.js';

export function newId() {
  return `f_crawl_${crypto.randomBytes(4).toString('hex')}`;
}

/** Normalize a URL for dedup: drop fragment, sort nothing, keep path+search. */
export function canonical(u: URL): string {
  return `${u.origin}${u.pathname}${u.search}`.replace(/\/$/, '') || u.origin;
}

/** Pull href/src targets and resolve them against the page URL. */
export function extractLinks(html: string, base: URL): URL[] {
  const out: URL[] = [];
  const re = /(?:href|src)\s*=\s*["']([^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const raw = m[1].trim();
    if (!raw || raw.startsWith('javascript:') || raw.startsWith('mailto:') ||
        raw.startsWith('tel:') || raw.startsWith('data:')) continue;
    try {
      out.push(new URL(raw, base));
    } catch { /* skip malformed */ }
  }
  return out;
}

/** Collect external resource references (for mixed-content detection). */
export function extractResources(html: string, base: URL): URL[] {
  const out: URL[] = [];
  const re = /<(?:script|img|iframe|link|source|audio|video)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    try { out.push(new URL(m[1], base)); } catch { /* skip */ }
  }
  return out;
}

export function extractTitle(html: string): string | undefined {
  const m = /<title[^>]*>([^<]{0,200})<\/title>/i.exec(html);
  return m ? m[1].trim() : undefined;
}

/** Parse <form> blocks with their inputs from page HTML. */
export function extractForms(html: string, pageUrl: URL): CrawlForm[] {
  const forms: CrawlForm[] = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm: RegExpExecArray | null;
  while ((fm = formRe.exec(html)) !== null) {
    const attrs = fm[1] || '';
    const body = fm[2] || '';
    const actionMatch = /\baction\s*=\s*["']([^"']*)["']/i.exec(attrs);
    const methodMatch = /\bmethod\s*=\s*["']([^"']*)["']/i.exec(attrs);
    let action = actionMatch ? actionMatch[1] : pageUrl.href;
    let resolvedAction: URL | null = null;
    try { resolvedAction = new URL(action || pageUrl.href, pageUrl); action = resolvedAction.href; } catch { /* keep raw */ }
    const method = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();

    const inputs: string[] = [];
    let hasPassword = false;
    let hasCsrfToken = false;
    const inputRe = /<(?:input|textarea|select)\b([^>]*)>/gi;
    let im: RegExpExecArray | null;
    while ((im = inputRe.exec(body)) !== null) {
      const ia = im[1] || '';
      const nameMatch = /\bname\s*=\s*["']([^"']*)["']/i.exec(ia);
      const typeMatch = /\btype\s*=\s*["']([^"']*)["']/i.exec(ia);
      const name = nameMatch ? nameMatch[1] : '';
      const type = typeMatch ? typeMatch[1].toLowerCase() : 'text';
      if (name) inputs.push(name);
      if (type === 'password') hasPassword = true;
      if (/csrf|xsrf|token|authenticity|nonce/i.test(name)) hasCsrfToken = true;
    }
    // Some frameworks expose the CSRF token via a meta tag rather than a hidden input.
    if (!hasCsrfToken && /<meta[^>]+name\s*=\s*["'][^"']*(?:csrf|xsrf)[^"']*["']/i.test(html)) {
      hasCsrfToken = true;
    }

    const insecure = !!resolvedAction && resolvedAction.protocol === 'http:';
    forms.push({ pageUrl: pageUrl.href, action, method, inputs, hasPassword, hasCsrfToken, insecure });
  }
  return forms;
}
