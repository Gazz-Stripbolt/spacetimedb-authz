// End-to-end through the demo page in headless Chromium: create a workspace, write a doc,
// invite someone by link, and check what they can and can't do.
//
//   PAGE=http://127.0.0.1:3000/v1/database/authz-rust/route/ npx tsx tests/page.test.mts
//   SHOTS=docs/ ... also saves light/dark screenshots.
import assert from 'node:assert/strict';
import { chromium, type Page } from 'playwright';

const PAGE = process.env.PAGE ?? 'http://127.0.0.1:3000/v1/database/authz-rust/route/';
const SHOTS = process.env.SHOTS;
const sep = PAGE.includes('?') ? '&' : '?';
const browser = await chromium.launch();
let passed = 0;
const pages: Page[] = [];
async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
  } catch (e) {
    if (process.env.FAILSHOTS) {
      for (const [i, p] of pages.entries()) {
        await p.screenshot({ path: `${process.env.FAILSHOTS}/fail-${i}.png` }).catch(() => {});
        console.log(`page ${i}`, await p.evaluate(() => {
          const a = (window as any).__a;
          const mine = [...a.visible.iter()].filter((v: any) => v.identity.isEqual(a.identity)).map((v: any) => `${v.scopeId}:${v.perm}`);
          return { me: a.identity.toHexString().slice(0, 12), mine, docs: [...a.doc.iter()].map((d: any) => `${d.scopeId}:${d.title}`), grants: [...a.grant.iter()].length, scopes: [...a.scope.iter()].map((s: any) => s.id) };
        }).catch((e) => String(e)));
      }
    }
    throw e;
  }
  passed++;
  console.log(`  ok  ${name}`);
}
async function open(scheme: 'light' | 'dark', url = `${PAGE}${sep}fresh=1&test=1`): Promise<Page> {
  const ctx = await browser.newContext({ colorScheme: scheme, viewport: { width: 1180, height: 820 }, deviceScaleFactor: SHOTS ? 2 : 1 });
  const p = await ctx.newPage();
  p.on('pageerror', (e) => console.error('[page]', e.message));
  pages.push(p);
  await p.goto(url);
  await p.waitForFunction(() => document.querySelector('#status')?.textContent?.startsWith('connected'));
  return p;
}

try {
  for (const scheme of SHOTS ? (['light', 'dark'] as const) : (['light'] as const)) {
    const ws = `Acme ${scheme} ${Date.now() % 10000}`;
    const alice = await open(scheme);
    await alice.evaluate(() => (window as any).__a.setName('Alice'));
    const bob = await open(scheme);
    await bob.evaluate(() => (window as any).__a.setName('Bob'));
    const carol = await open(scheme);
    await carol.evaluate(() => (window as any).__a.setName('Carol'));
    let link = '';

    await test(`[${scheme}] create a workspace, a project and a doc`, async () => {
      await alice.fill('#new-ws-name', ws);
      await alice.click('#new-ws button');
      await alice.waitForFunction((n) => document.querySelector('h2.title')?.textContent === n, ws);
      assert.ok(await alice.locator('.chip.role', { hasText: 'admin' }).count());
      await alice.fill('input[placeholder="Project name"]', 'Launch');
      await alice.click('.card:has-text("New project inside") button');
      await alice.locator('.scope', { hasText: 'Launch' }).click();
      await alice.fill('input[placeholder="Title"]', 'Press kit');
      await alice.fill('textarea', 'Logos, screenshots and the one-liner.');
      await alice.click('button:has-text("Save")');
      await alice.waitForSelector('.row:has-text("Press kit")');
    });

    await test(`[${scheme}] invite by link: the guest sees docs but can't write`, async () => {
      await alice.locator('.scope', { hasText: ws }).click();
      await alice.click('.tab:has-text("Invites")');
      await alice.selectOption('.card:has-text("Invite someone") select >> nth=0', { label: 'viewer' });
      await alice.click('button:has-text("Create link")');
      await alice.waitForSelector('.link:has-text("invite=")');
      link = (await alice.locator('.link').textContent())!;
      await bob.goto(link); // no `fresh`, so Bob keeps his identity
      await bob.waitForFunction(() => document.querySelector('#status')?.textContent?.startsWith('connected'));
      await bob.locator('.scope', { hasText: 'Launch' }).click();
      await bob.waitForSelector('.row:has-text("Press kit")');
      await bob.fill('input[placeholder="Title"]', 'Sneaky');
      await bob.click('button:has-text("Save")');
      await bob.waitForSelector('#toast.show:has-text("permission denied")');
    });

    await test(`[${scheme}] an outsider sees nothing; a grant makes things appear live`, async () => {
      assert.equal(await carol.locator('.scope').count(), 0);
      await alice.locator('.scope', { hasText: ws }).click();
      await alice.click('.tab:has-text("Members")');
      // By identity: earlier runs on the same database left other "Carol"s around.
      const carolId = await carol.evaluate(() => (window as any).__a.identity.toHexString());
      await alice.selectOption('.card:has-text("Grant a role") select >> nth=0', carolId);
      await alice.selectOption('.card:has-text("Grant a role") select >> nth=1', { label: 'editor' });
      await alice.click('.card:has-text("Grant a role") button.primary');
      await carol.waitForSelector(`.scope:has-text("${ws}")`);
      await carol.locator('.scope', { hasText: 'Launch' }).click();
      await carol.waitForSelector('.row:has-text("Press kit")');
    });

    if (SHOTS) {
      await alice.click('.tab:has-text("Members")');
      await alice.waitForSelector('#toast.show', { state: 'detached' }).catch(() => {}); // let the toast fade
      await alice.screenshot({ path: `${SHOTS}/demo-${scheme}.png` });
    }
    for (const p of [alice, bob, carol]) await p.context().close();
  }
} finally {
  await browser.close();
}
console.log(`\n${passed} passed`);
