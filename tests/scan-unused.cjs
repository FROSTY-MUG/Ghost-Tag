/**
 * @file scan-unused.cjs
 * @summary Ad-hoc dead-code scan for the plain-JS web/desktop sources that
 * CodeQL reports as "unused variable / function / import" notes.
 * Not part of the build; invoked manually and from the verification runbook.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

const targets = [
  'web/app.js',
  'web/supabase.js',
  'web/crypto-simulator.js',
  'web/wordlist.js',
  'desktop/src/apdu.js',
  'desktop/src/server.js',
  'desktop/src/index.js',
];

const BUILTINS = new Set([
  'window', 'document', 'console', 'localStorage', 'sessionStorage', 'navigator',
  'crypto', 'fetch', 'WebSocket', 'NDEFReader', 'AbortSignal', 'AbortController',
  'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'alert', 'confirm',
  'prompt', 'URL', 'Blob', 'FileReader', 'File', 'TextEncoder', 'TextDecoder',
  'atob', 'btoa', 'Uint8Array', 'ArrayBuffer', 'DataView', 'Promise', 'Map', 'Set',
  'WeakMap', 'WeakSet', 'JSON', 'Math', 'Object', 'Array', 'String', 'Number',
  'Boolean', 'Date', 'Error', 'TypeError', 'RangeError', 'require', 'module',
  'exports', '__dirname', '__filename', 'globalThis', 'process', 'Buffer',
  'Float32Array', 'Int32Array', 'Uint16Array', 'Int8Array', 'isNaN', 'parseInt',
  'parseFloat', 'undefined', 'event', 'this', 'arguments', 'structuredClone',
  'location', 'history', 'requestAnimationFrame', 'performance', 'Image', 'matchMedia',
]);

function stripCommentsAndStrings(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const next = src[i + 1];
    if (c === '/' && next === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && next === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (c === "'" || c === '"') {
      const quote = c;
      out += ' ';
      i++;
      while (i < n) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === quote) { i++; break; }
        i++;
      }
      continue;
    }
    if (c === '`') {
      out += ' ';
      i++;
      let depth = 0;
      while (i < n) {
        if (src[i] === '\\') { i += 2; out += '  '; continue; }
        if (depth === 0 && src[i] === '`') { i++; break; }
        if (src[i] === '$' && src[i + 1] === '{') {
          depth++;
          out += '  ';
          i += 2;
          continue;
        }
        if (depth > 0 && src[i] === '}') {
          depth--;
          out += ' ';
          i++;
          continue;
        }
        if (depth > 0) {
          out += src[i];
        } else {
          out += (src[i] === '\n' ? '\n' : ' ');
        }
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

const declarations = [
  // function NAME(
  /(?:^|[^.\w$])function\s+([A-Za-z_$][\w$]*)/g,
  // const/let/var NAME =
  /(?:^|[^.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g,
  // destructured: const { a, b: c } =
  /(?:const|let|var)\s*\{([^}]*)\}\s*=/g,
  // class NAME
  /(?:^|[^.\w$])class\s+([A-Za-z_$][\w$]*)/g,
];

const findings = [];

for (const rel of targets) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) continue;
  const raw = fs.readFileSync(abs, 'utf-8');
  const code = stripCommentsAndStrings(raw);

  const names = new Map();
  const lineOf = (idx) => raw.slice(0, idx).split('\n').length;

  for (const re of declarations) {
    let m;
    re.lastIndex = 0;
    while ((m = re.exec(code)) !== null) {
      if (m[1] && re.source.includes('{')) {
        for (const part of m[1].split(',')) {
          const name = part.split(':').pop().trim().split('=')[0].trim();
          if (/^[A-Za-z_$][\w$]*$/.test(name)) {
            names.set(name, lineOf(m.index));
          }
        }
        continue;
      }
      const name = m[1];
      if (!names.has(name)) names.set(name, lineOf(m.index));
    }
  }

  for (const [name, line] of names) {
    if (BUILTINS.has(name)) continue;
    const escape = name.replace(/\$/g, '\\$');
    const uses = code.match(new RegExp(`(?<!(?:[a-zA-Z0-9_$\\]\\)]\\s*\\.|[\\w$]))${escape}(?![\\w$])`, 'g'));
    const count = uses ? uses.length : 0;
    if (count <= 1) {
      findings.push(`${rel}:${line}  unused declaration: ${name}`);
    }
  }
}

if (findings.length === 0) {
  console.log('No unused top-level declarations found in targeted web/desktop sources.');
} else {
  console.log(findings.join('\n'));
  process.exitCode = 1;
}
