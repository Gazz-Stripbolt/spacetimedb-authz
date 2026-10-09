// Protocol-level tests: real clients against a published authz demo module.
//
//   DB=authz-rust HOST=ws://127.0.0.1:3000 [FLAVOR=flat|ns] npx tsx tests/server.test.mts
//
// FLAVOR=ns for the TypeScript submodule (namespaced names), flat for Rust and C#.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { Identity, Timestamp } from 'spacetimedb';
import { connect, type Authz, type Flavor } from '../demo/web/src/api.ts';

const HOST = process.env.HOST ?? 'ws://127.0.0.1:3000';
const DB = process.env.DB ?? 'authz-rust';
const FLAVOR = (process.env.FLAVOR ?? 'flat') as Flavor;
const SERVER = process.env.SERVER ?? 'local';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const code = () => randomBytes(12).toString('hex');
const inSecs = (s: number) => new Timestamp(BigInt(Date.now() + s * 1000) * 1000n);

type C = Authz & { name: string; err: (p: Promise<unknown>) => Promise<string | null> };
async function client(name: string): Promise<C> {
  const a = await connect(FLAVOR, HOST, DB);
  await a.subscribeAll();
  await a.setName(name);
  return Object.assign(a, {
    name,
    err: async (p: Promise<unknown>) => {
      try {
        await p;
        return null;
      } catch (e) {
        return String((e as Error)?.message ?? e);
      }
    },
  });
}

const settle = () => sleep(150);
const scopes = (c: C) => [...c.scope.iter()].map((s) => s.name).sort();
const docs = (c: C) => [...c.doc.iter()].map((d) => d.title).sort();
const role = (c: C, name: string, scope = 0n) => [...c.role.iter()].find((r) => r.name === name && r.scopeId === scope)!;
const scopeId = (c: C, name: string) => [...c.scope.iter()].find((s) => s.name === name)!.id;
const grantsOf = (c: C, who: C) => [...c.grant.iter()].filter((g) => g.identity.isEqual(who.identity));
const denied = (m: string | null) => assert.match(m ?? 'allowed!', /permission denied|only hand out|only give|only change|can no longer|locked|isn't available/);

let passed = 0;
async function test(name: string, fn: () => Promise<void>) {
  await fn();
  passed++;
  console.log(`  ok  ${name}`);
}

const ws = `ws-${code().slice(0, 6)}`;
const alice = await client('alice');
const bob = await client('bob');
const carol = await client('carol');
const dave = await client('dave');
const eve = await client('eve'); // never gets anything

let W = 0n;
let P = 0n;
await test('workspace: creator becomes admin; nobody else sees it', async () => {
  await alice.createWorkspace(ws);
  await settle();
  W = scopeId(alice, ws);
  assert.ok(scopes(alice).includes(ws));
  assert.equal(grantsOf(alice, alice).length, 1);
  assert.equal(grantsOf(alice, alice)[0].roleId, role(alice, 'admin').id);
  assert.ok(!scopes(bob).includes(ws), 'bob sees no foreign scopes');
  assert.equal([...eve.grant.iter()].filter((g) => g.scopeId === W).length, 0, 'eve sees no grants');
});

await test('hierarchy: a grant on the workspace covers projects and docs below it', async () => {
  await alice.createScope(W, 'project', 'Roadmap');
  await settle();
  P = scopeId(alice, 'Roadmap');
  const s = [...alice.scope.iter()].find((x) => x.id === P)!;
  assert.deepEqual(s.path, [W]);
  await alice.createDoc(P, 'Q4 plan', 'ship it');
  await settle();
  assert.deepEqual(docs(alice), ['Q4 plan']);
  denied(await bob.err(bob.createDoc(P, 'nope', '')));
  assert.deepEqual(docs(bob), [], 'RLS hides the doc');
});

await test('grant: viewer sees the subtree live, but cannot write or grant', async () => {
  await alice.grantRole(bob.identity, role(alice, 'viewer').id, W);
  await settle();
  assert.deepEqual(docs(bob), ['Q4 plan']);
  assert.ok(scopes(bob).includes('Roadmap'), 'child scope visible through the parent grant');
  denied(await bob.err(bob.createDoc(P, 'nope', '')));
  denied(await bob.err(bob.grantRole(carol.identity, role(bob, 'viewer').id, W)));
  assert.equal([...bob.grant.iter()].filter((g) => g.scopeId === W).length, 2, 'members see the roster');
});

let lead = 0n;
await test('escalation: a lead can hand out only what they hold', async () => {
  await alice.createRole(W, 'lead', ['authz.grant'], [role(alice, 'editor').id]);
  await settle();
  lead = role(alice, 'lead', W).id;
  assert.deepEqual([...role(alice, 'lead', W).effective].sort(), ['authz.grant', 'doc.read', 'doc.write']);
  await alice.grantRole(bob.identity, lead, W);
  await settle();
  denied(await bob.err(bob.grantRole(carol.identity, role(bob, 'admin').id, P)));
  denied(await bob.err(bob.grantRole(carol.identity, role(bob, 'owner').id, W)));
  assert.equal(await bob.err(bob.grantRole(carol.identity, role(bob, 'editor').id, P)), null);
  assert.equal(await bob.err(bob.grantRole(dave.identity, lead, W)), null);
  denied(await bob.err(bob.createRole(W, 'sneaky', ['doc.delete'], [])));
  denied(await bob.err(bob.revokeGrant(grantsOf(bob, alice)[0].id)));
  denied(await bob.err(bob.updateRole(lead, ['authz.grant', 'doc.delete'], [])));
  await settle();
  assert.deepEqual(docs(carol), ['Q4 plan']);
  assert.equal(await carol.err(carol.createDoc(P, 'carol notes', '')), null);
  denied(await carol.err(carol.createDoc(W, 'top level', '')));
});

await test('roles: inheritance changes apply to holders immediately; cycles rejected', async () => {
  const docId = [...alice.doc.iter()].find((d) => d.title === 'carol notes')!.id;
  denied(await bob.err(bob.deleteDoc(docId)));
  await alice.updateRole(lead, ['authz.grant', 'doc.delete'], [role(alice, 'editor').id]);
  await settle();
  assert.equal(await bob.err(bob.deleteDoc(docId)), null);
  assert.match((await alice.err(alice.updateRole(lead, ['authz.grant'], [lead]))) ?? '', /inherit themselves/);
  assert.match((await alice.err(alice.updateRole(role(alice, 'admin').id, [], []))) ?? '', /system roles/);
  assert.match((await alice.err(alice.createRole(W, 'bad', ['doc.*.x'], []))) ?? '', /bad permission/);
  assert.match((await alice.err(alice.deleteRole(lead))) ?? '', /still granted/);
});

await test('expiry: a timed grant disappears on time, with an audit entry', async () => {
  await alice.grantRole(eve.identity, role(alice, 'viewer').id, P, inSecs(1.5));
  await settle();
  assert.deepEqual(docs(eve), ['Q4 plan']);
  assert.match((await alice.err(alice.grantRole(eve.identity, role(alice, 'viewer').id, P, inSecs(-5)))) ?? '', /past/);
  await sleep(2200);
  assert.deepEqual(docs(eve), [], 'gone after expiry');
  assert.equal(grantsOf(eve, eve).length, 0);
  assert.ok([...alice.audit.iter()].some((a) => a.action === 'expire' && a.target.isEqual(eve.identity)));
});

await test('invites: use limits, expiry, short codes, and inviters losing rights', async () => {
  const viewer = role(alice, 'viewer').id;
  const c1 = code();
  await alice.createInvite(c1, viewer, W, 2, undefined, 0n);
  assert.match((await alice.err(alice.createInvite('short', viewer, W, 1, undefined, 0n))) ?? '', /16-128/);
  denied(await carol.err(carol.createInvite(code(), viewer, P, 1, undefined, 0n)));
  const [x, y, z] = await Promise.all([client('x'), client('y'), client('z')]);
  assert.equal(await x.err(x.redeemInvite(c1)), null);
  assert.equal(await y.err(y.redeemInvite(c1)), null);
  assert.match((await z.err(z.redeemInvite(c1))) ?? '', /invalid invite/, 'used up');
  await settle();
  assert.deepEqual(docs(x), ['Q4 plan']);
  // expiry
  const c2 = code();
  await alice.createInvite(c2, viewer, W, 0, inSecs(1), 0n);
  await sleep(1500);
  assert.match((await z.err(z.redeemInvite(c2))) ?? '', /invalid invite|expired/);
  // an inviter who loses the right can't be redeemed against
  await alice.createRole(W, 'recruiter', ['authz.invite'], [viewer]);
  await settle();
  await alice.grantRole(dave.identity, role(alice, 'recruiter', W).id, W);
  await settle();
  const c3 = code();
  assert.equal(await dave.err(dave.createInvite(c3, viewer, W, 5, undefined, 0n)), null);
  for (const g of grantsOf(alice, dave).filter((g) => g.roleId === role(alice, 'recruiter', W).id)) await alice.revokeGrant(g.id);
  denied(await z.err(z.redeemInvite(c3)));
  // timed grants from an invite
  const c4 = code();
  await alice.createInvite(c4, viewer, P, 1, undefined, 1n);
  await z.redeemInvite(c4);
  await settle();
  assert.deepEqual(docs(z), ['Q4 plan']);
  await sleep(1700);
  assert.deepEqual(docs(z), [], 'invite grant_ttl expired');
  for (const c of [x, y, z]) c.conn.disconnect();
});

await test('revocation and leaving: access disappears live', async () => {
  for (const g of grantsOf(alice, bob)) await alice.revokeGrant(g.id);
  await settle();
  assert.deepEqual(docs(bob), []);
  assert.ok(!scopes(bob).includes(ws));
  const mine = grantsOf(carol, carol)[0];
  await carol.revokeGrant(mine.id); // leave
  await settle();
  assert.deepEqual(docs(carol), []);
});

await test('audit: managers see the scope log, nobody else does', async () => {
  const actions = new Set([...alice.audit.iter()].filter((a) => a.scopeId === W || a.scopeId === P).map((a) => a.action));
  for (const a of ['grant', 'revoke', 'role.create', 'role.update', 'invite.create', 'invite.redeem', 'scope.create']) assert.ok(actions.has(a), `has ${a}`);
  assert.equal([...bob.audit.iter()].length, 0, 'bob (no longer a member) sees none');
  assert.equal([...eve.audit.iter()].length, 0);
});

await test('privacy: an outsider sees no scopes, grants, invites or docs of the workspace', async () => {
  const outsider = await client('outsider');
  assert.equal([...outsider.scope.iter()].filter((s) => s.id === W || s.id === P).length, 0);
  assert.equal([...outsider.grant.iter()].length, 0);
  assert.equal([...outsider.invite.iter()].length, 0);
  assert.equal([...outsider.doc.iter()].length, 0);
  const err = await new Promise<string>((res) =>
    outsider.conn.subscriptionBuilder().onApplied(() => res('subscribed!')).onError((_c, e) => res(String(e)))
      .subscribe([FLAVOR === 'ns' ? 'SELECT * FROM authz.invite_codes' : 'SELECT * FROM authz_invite_code'])
  );
  assert.match(err, /private|no such table|not.*found/i, 'invite codes are private');
  outsider.conn.disconnect();
});

await test('global grants: a global role reaches every scope', async () => {
  // Granted through the CLI as the database owner (the only one with `*` after bootstrap).
  const viewer = role(alice, 'viewer').id;
  const reducer = FLAVOR === 'ns' ? 'authz.grant_role' : 'authz_grant_role';
  try {
    execFileSync('spacetime', ['call', '-s', SERVER, DB, reducer, dave.identity.toHexString(), viewer.toString(), '0', '{"none":[]}'], { stdio: 'pipe' });
  } catch (e) {
    throw new Error(`spacetime call failed: ${(e as { stderr?: Buffer }).stderr?.toString()}`);
  }
  await sleep(300);
  assert.ok(docs(dave).includes('Q4 plan'), 'global viewer sees docs everywhere');
  assert.ok(scopes(dave).includes(ws));
});

await test('scope delete: removes the subtree, its grants and the demo docs', async () => {
  denied(await dave.err(dave.deleteScope(W)));
  await alice.deleteScope(W);
  await settle();
  assert.deepEqual(scopes(alice).filter((s) => s === ws || s === 'Roadmap'), []);
  assert.equal(grantsOf(alice, alice).length, 0);
  assert.equal([...alice.doc.iter()].length, 0);
});

console.log(`\n${passed} passed`);
for (const c of [alice, bob, carol, dave, eve]) c.conn.disconnect();
process.exit(0);
