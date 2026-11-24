/**
 * @file webSyntaxAndBuild.test.ts
 * @summary Automated validation of web app JavaScript syntax, AST validity, and bundle build integrity.
 */

declare const __dirname: string;

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const vm = require('vm');

describe('Ghost-Tag Web Client Syntax & Build Integrity', () => {
  const webDir = path.resolve(__dirname, '../../web');

  const webJsFiles = [
    'app.js',
    'supabase.js',
    'crypto-simulator.js',
    'wordlist.js',
  ];

  test.each(webJsFiles)('file %s has valid JavaScript syntax (node --check)', (fileName) => {
    const filePath = path.join(webDir, fileName);
    expect(fs.existsSync(filePath)).toBe(true);

    expect(() => {
      execSync(`node --check "${filePath}"`, { stdio: 'pipe' });
    }).not.toThrow();
  });

  test('web/app.js parses cleanly into V8 AST via vm.Script without syntax errors', () => {
    const appJsPath = path.join(webDir, 'app.js');
    const source = fs.readFileSync(appJsPath, 'utf-8');

    expect(() => {
      const script = new vm.Script(source, { filename: 'web/app.js' });
      expect(script).toBeDefined();
    }).not.toThrow();
  });

  test('web/supabase.js exports getStatus() and required zero-knowledge API methods', () => {
    // In CommonJS Node environment, web/supabase.js exports via module.exports
    // In Browser environment, it attaches to window.GhostSupabase
    const GhostSupabase = require('../../web/supabase.js');

    expect(typeof GhostSupabase).toBe('object');
    expect(typeof GhostSupabase.getStatus).toBe('function');
    expect(typeof GhostSupabase.getConfig).toBe('function');
    expect(typeof GhostSupabase.saveConfig).toBe('function');
    expect(typeof GhostSupabase.deriveAccountId).toBe('function');
    expect(typeof GhostSupabase.deriveRecoveryAuthSecret).toBe('function');
    expect(typeof GhostSupabase.computeRecoveryVerifier).toBe('function');
    expect(typeof GhostSupabase.recoverVaultWithVerifier).toBe('function');

    const status = GhostSupabase.getStatus();
    expect(status).toHaveProperty('configured');
    expect(status).toHaveProperty('label');
    expect(status).toHaveProperty('status');
  });

  test('web production build succeeds and outputs valid artifacts', () => {
    if (!fs.existsSync(path.join(webDir, 'node_modules'))) {
      execSync('npm --prefix web ci', { stdio: 'pipe', timeout: 60000 });
    }
    expect(() => {
      execSync('npm --prefix web run build', { stdio: 'pipe', timeout: 30000 });
    }).not.toThrow();

    const distHtml = path.join(webDir, 'dist/index.html');
    expect(fs.existsSync(distHtml)).toBe(true);
    const htmlContent = fs.readFileSync(distHtml, 'utf-8');
    expect(htmlContent).toContain('Ghost-Tag');

    // Regression guard for /app/*.html hash route support & keyboard-focusable header buttons
    const srcHtml = fs.readFileSync(path.join(webDir, 'index.html'), 'utf-8');
    expect(srcHtml).toMatch(/<button[^>]+id="headerAccountLink"/);
    expect(srcHtml).toMatch(/<button[^>]+id="headerRecoveryLink"/);
    expect(srcHtml).toMatch(/<button[^>]+id="headerSettingsLink"/);

    const appJsContent = fs.readFileSync(path.join(webDir, 'app.js'), 'utf-8');
    for (const h of ["'app'", "'bulk'", "'write'", "'scan'", "'recovery'", "'settings'"]) {
      expect(appJsContent).toContain(h);
    }
  });
});
