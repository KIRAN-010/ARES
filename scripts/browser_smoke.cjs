/* Real browser smoke test. Run after building frontend, with playwright installed.
 * MJ_PYTHON can point to an existing test venv; CHROMIUM_EXECUTABLE is optional.
 * All data and services are temporary; the screenshot contains synthetic fixtures.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { createRequire } = require('module');
const root = path.resolve(__dirname, '..');
const localRequire = createRequire(path.join(root, 'frontend/package.json'));
let chromium;
try { ({ chromium } = localRequire('playwright')); } catch { ({ chromium } = require('playwright')); }

async function main() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'mj-browser-'));
  const python = process.env.MJ_PYTHON || path.join(root, '.venv/bin/python');
  const env = { ...process.env, MJ_DATA_DIR: temp, MJ_PORT: '8765', MJ_LAB_PORT: '8091', MJ_ENABLE_VM: '0' };
  delete env.MJ_TOKEN;
  const children = ['lab', 'serve'].map(command => spawn(python, ['-m', 'mj.cli', command], { cwd: root, env, stdio: 'ignore' }));
  let browser;
  try {
    let ready = false;
    for (let i = 0; i < 100; i++) {
      try {
        ready = (await fetch('http://127.0.0.1:8765/health')).ok && (await fetch('http://127.0.0.1:8091/health')).ok;
        if (ready) break;
      } catch {}
      await new Promise(r => setTimeout(r, 100));
    }
    if (!ready) throw new Error('Temporary MJ services did not start');
    browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_EXECUTABLE || undefined,
                                     args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto('http://127.0.0.1:8765');
    await page.getByPlaceholder('Run mj token in your terminal').fill(fs.readFileSync(path.join(temp, 'operator-token'), 'utf8').trim());
    await page.getByRole('button', { name: 'Unlock console' }).click();
    await page.getByRole('heading', { name: 'Security at a glance' }).waitFor();
    await page.getByRole('button', { name: 'Run lab demonstration' }).click();
    await page.getByText('Executed 6 bounded tools;', { exact: false }).waitFor({ timeout: 20000 });
    await page.getByRole('button', { name: /^Recovery/ }).first().click();
    await page.getByPlaceholder('Record why you approve or reject this action').fill('Reviewed synthetic evidence and approved the lab fix');
    await page.getByRole('button', { name: 'Approve & execute' }).click();
    await page.getByText('verified', { exact: true }).waitFor({ timeout: 10000 });
    console.log('PASS: browser login, assessment, human approval and verified remediation');
    await page.getByRole('button', { name: 'Research', exact: true }).click();
    await page.getByRole('button', { name: 'Run 256 deterministic mutations' }).click();
    await page.getByText('"fixed_parser_rejects": true', { exact: false }).waitFor();
    await page.getByRole('button', { name: 'Infrastructure', exact: true }).click();
    await page.getByRole('button', { name: 'Assess configuration' }).click();
    await page.getByRole('dialog').waitFor();
    if (!(await page.getByRole('dialog').textContent()).includes('PRIVILEGED')) throw new Error('Manifest result missing');
    await page.getByRole('button', { name: 'Close', exact: true }).click();
    await page.getByRole('button', { name: 'Audit', exact: true }).click();
    await page.getByText('"valid": true', { exact: false }).waitFor();
    console.log('PASS: research, infrastructure and audit screens');
    await page.getByRole('button', { name: 'Overview', exact: true }).click();
    fs.mkdirSync(path.join(root, 'docs/images'), { recursive: true });
    await page.screenshot({ path: path.join(root, 'docs/images/dashboard.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw new Error('Mobile horizontal overflow');
    if (errors.length) throw new Error(errors.join('\n'));
    console.log('PASS: desktop/mobile layout bounds; no browser runtime exceptions');
  } finally {
    if (browser) await browser.close();
    for (const child of children) child.kill('SIGTERM');
    await Promise.all(children.map(child => child.exitCode !== null ? Promise.resolve() : new Promise(r => child.on('exit', r))));
    fs.rmSync(temp, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
