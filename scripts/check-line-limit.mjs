#!/usr/bin/env node
// Enforces the project's modularity rule: no source file exceeds MAX_LINES.
// Test files are exempt (a thorough suite is not a modularity problem).
// Written in Node rather than shell so it runs identically on Windows, macOS,
// and Linux, and in CI.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const MAX_LINES = 200;
const ROOTS = ['server', 'src'];
const EXTRA_FILES = ['server.ts'];
const EXTENSIONS = ['.ts', '.tsx'];
const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage', '.git']);

const isTest = (p) => /\.test\.tsx?$/.test(p);
const isSource = (p) => EXTENSIONS.some((e) => p.endsWith(e)) && !isTest(p);

// Matches `wc -l` semantics: a trailing newline terminates the last line rather
// than starting an empty one, so it must not count as an extra line.
function countLines(file) {
  const parts = readFileSync(file, 'utf8').split('\n');
  if (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
  return parts.length;
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(join(dir, entry.name), out);
    } else if (isSource(entry.name)) {
      out.push(join(dir, entry.name));
    }
  }
  return out;
}

const files = [];
for (const root of ROOTS) {
  try {
    if (statSync(root).isDirectory()) walk(root, files);
  } catch {
    /* root not present — skip */
  }
}
for (const f of EXTRA_FILES) {
  try {
    if (statSync(f).isFile() && isSource(f)) files.push(f);
  } catch {
    /* optional */
  }
}

const offenders = files
  .map((f) => ({ file: relative(process.cwd(), f).split(sep).join('/'), lines: countLines(f) }))
  .filter((f) => f.lines > MAX_LINES)
  .sort((a, b) => b.lines - a.lines);

if (offenders.length > 0) {
  console.error(`\n✖ ${offenders.length} file(s) exceed the ${MAX_LINES}-line limit:\n`);
  for (const o of offenders) console.error(`   ${String(o.lines).padStart(5)}  ${o.file}`);
  console.error(`\nSplit the file into focused modules, or move cohesive logic into a helper.\n`);
  process.exit(1);
}

const largest = files.map(countLines).reduce((a, b) => Math.max(a, b), 0);
console.log(`✓ ${files.length} source files within the ${MAX_LINES}-line limit (largest: ${largest}).`);
