/**
 * Demo: a team workspace, in TypeScript, using `spacetimedb-authz` as a submodule. Same behaviour
 * as demo/rust and demo/csharp; serves the web client at /route/.
 */
import { schema, table, t, Router, SyncResponse, SenderError } from 'spacetimedb/server';
import * as authz from 'spacetimedb-authz';
import PAGE from './page.gen';

const demoProfile = table({ name: 'demo_profile', public: true }, { identity: t.identity().primaryKey(), name: t.string() });

const demoDoc = table(
  { name: 'demo_doc', public: true },
  {
    id: t.u64().primaryKey().autoInc(),
    scopeId: t.u64().index('btree'),
    title: t.string(),
    body: t.string(),
    author: t.identity(),
    updatedAt: t.timestamp(),
  }
);

const spacetimedb = schema({ demoProfile, demoDoc, authz });
export default spacetimedb;

// ---------------------------------------------------------------------------
// authz wiring: the row-level-security rules (submodules can't declare them)
// ---------------------------------------------------------------------------

const rls = authz.rlsSql('authz');
export const authzGrants = spacetimedb.clientVisibilityFilter.sql(rls.grants);
export const authzScopes = spacetimedb.clientVisibilityFilter.sql(rls.scopes);
export const authzInvites = spacetimedb.clientVisibilityFilter.sql(rls.invites);
export const authzAudit = spacetimedb.clientVisibilityFilter.sql(rls.audit);
/** Docs are visible to people holding doc.read in the doc's scope (or above it). */
export const demoDocRead = spacetimedb.clientVisibilityFilter.sql(authz.rlsFor('demo_doc', 'scope_id', 'doc.read', 'authz'));

export const init = spacetimedb.init((ctx) => {
  const az = ctx.as.authz;
  authz.configure(az, { watch: ['doc.read'], clientsDeleteScopes: false });
  authz.bootstrap(az, ctx.sender);
  const viewer = authz.newRole(az, authz.GLOBAL, 'viewer', ['doc.read'], []);
  const editor = authz.newRole(az, authz.GLOBAL, 'editor', ['doc.write'], [viewer]);
  authz.newRole(az, authz.GLOBAL, 'admin', ['doc.delete', 'authz.grant', 'authz.invite', 'authz.role', 'authz.scope.create', 'authz.scope.delete', 'authz.audit'], [editor]);
});

export const onConnect = spacetimedb.clientConnected((ctx) => {
  if (!ctx.db.demoProfile.identity.find(ctx.sender)) {
    ctx.db.demoProfile.insert({ identity: ctx.sender, name: `guest-${ctx.sender.toHexString().slice(-4)}` });
  }
});

// ---------------------------------------------------------------------------
// The app
// ---------------------------------------------------------------------------

export const demoSetName = spacetimedb.reducer({ name: t.string() }, (ctx, { name }) => {
  name = name.trim();
  if (name.length === 0 || [...name].length > 24) throw new SenderError('name must be 1-24 characters');
  ctx.db.demoProfile.identity.update({ identity: ctx.sender, name });
});

/** Anyone can start a workspace; the module makes them its admin. */
export const demoCreateWorkspace = spacetimedb.reducer({ name: t.string() }, (ctx, { name }) => {
  const ws = authz.newScope(ctx.as.authz, authz.GLOBAL, 'workspace', name.trim(), ctx.sender);
  const admin = authz.findRole(ctx.as.authz, authz.GLOBAL, 'admin');
  if (admin === undefined) throw new SenderError('admin role missing');
  authz.addGrant(ctx.as.authz, ctx.sender, admin, ws, undefined, undefined);
});

/** Delete a workspace or project: its docs first, then the scopes, grants and invites. */
export const demoDeleteScope = spacetimedb.reducer({ scopeId: t.u64() }, (ctx, { scopeId }) => {
  authz.require(ctx.as.authz, authz.PERM_SCOPE_DELETE, scopeId);
  for (const s of authz.subtree(ctx.as.authz, scopeId)) {
    for (const d of [...ctx.db.demoDoc.scopeId.filter(s)]) ctx.db.demoDoc.id.delete(d.id);
  }
  authz.removeScope(ctx.as.authz, scopeId, ctx.sender);
});

export const demoCreateDoc = spacetimedb.reducer({ scopeId: t.u64(), title: t.string(), body: t.string() }, (ctx, { scopeId, title, body }) => {
  authz.require(ctx.as.authz, 'doc.write', scopeId);
  title = title.trim();
  if (title.length === 0 || [...title].length > 80 || body.length > 4000) throw new SenderError('title 1-80 characters, body up to 4000');
  ctx.db.demoDoc.insert({ id: 0n, scopeId, title, body, author: ctx.sender, updatedAt: ctx.timestamp });
});

export const demoUpdateDoc = spacetimedb.reducer({ id: t.u64(), body: t.string() }, (ctx, { id, body }) => {
  const doc = ctx.db.demoDoc.id.find(id);
  if (!doc) throw new SenderError('no such doc');
  authz.require(ctx.as.authz, 'doc.write', doc.scopeId);
  if (body.length > 4000) throw new SenderError('body up to 4000');
  ctx.db.demoDoc.id.update({ ...doc, body, updatedAt: ctx.timestamp });
});

export const demoDeleteDoc = spacetimedb.reducer({ id: t.u64() }, (ctx, { id }) => {
  const doc = ctx.db.demoDoc.id.find(id);
  if (!doc) throw new SenderError('no such doc');
  authz.require(ctx.as.authz, 'doc.delete', doc.scopeId);
  ctx.db.demoDoc.id.delete(id);
});

/** Benchmark: n permission checks for the caller in scopeId. */
export const demoBench = spacetimedb.reducer({ scopeId: t.u64(), n: t.u32() }, (ctx, { scopeId, n }) => {
  let yes = 0;
  for (let i = 0; i < n; i++) if (authz.can(ctx.as.authz, ctx.sender, i % 2 === 0 ? 'doc.write' : 'doc.nope', scopeId)) yes++;
  console.info(`demo_bench: ${yes}/${n} allowed`);
});

// The shared web client, told that this module uses the submodule's namespaced names.
const NS_PAGE = PAGE.replace('data-flavor="flat"', 'data-flavor="ns"');
export const page = spacetimedb.httpHandler(
  () => new SyncResponse(NS_PAGE, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' } })
);
export const router = spacetimedb.httpRouter(new Router().get('/', page));
