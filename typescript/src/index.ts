/**
 * # spacetimedb-authz: roles, scopes and grants, as a SpacetimeDB submodule
 *
 * The TypeScript twin of `rust/authz.rs` and `csharp/Authz.cs`. Roles hold permission strings
 * (`doc.write`, `doc.*`, `*`) and inherit other roles; scopes form a tree and grants apply below
 * the scope they're on (scope 0 is global); grants can expire exactly on time; invites grant a role
 * on redemption; clients can only hand out what they hold; every change is audited; and
 * row-level security shows clients only the scopes they're in.
 *
 * Mount it with `schema({ ..., authz })`, then see `README.md` for the lines a consumer adds:
 * submodules can't declare RLS filters or an init reducer, so the consumer does.
 */
import { schema, table, t, SenderError } from 'spacetimedb/server';
import type { ReducerCtx } from 'spacetimedb/server';
import { Identity, ScheduleAt, Timestamp } from 'spacetimedb';

// ---------------------------------------------------------------------------
// Permissions this module checks itself
// ---------------------------------------------------------------------------

export const PERM_GRANT = 'authz.grant';
export const PERM_INVITE = 'authz.invite';
export const PERM_ROLE = 'authz.role';
export const PERM_SCOPE_CREATE = 'authz.scope.create';
export const PERM_SCOPE_DELETE = 'authz.scope.delete';
export const PERM_AUDIT = 'authz.audit';
/** The `perm` value in `visible` meaning "has any grant reaching this scope". */
export const MEMBER = '';
export const GLOBAL = 0n;

const MAX_NAME = 64;
const MAX_PERMS = 64;
const MIN_INVITE_CODE = 16;

export const AuthzSettings = t.object('AuthzSettings', {
  /** Permissions to materialise in `visible` for your own RLS rules (e.g. `doc.read`). */
  watch: t.array(t.string()),
  /** Allow the `delete_scope` reducer (off: delete through your own reducer that cleans up first). */
  clientsDeleteScopes: t.bool(),
});
export type Settings = { watch: string[]; clientsDeleteScopes: boolean };

// ---------------------------------------------------------------------------
// Tables (they live under the consumer's namespace, e.g. `authz.grants`)
// ---------------------------------------------------------------------------

const config = table({ name: 'config' }, { key: t.u8().primaryKey(), settings: AuthzSettings });

/** Roles. `scopeId` 0 = usable everywhere; otherwise only in that scope and below. */
const roles = table(
  { name: 'roles', public: true, indexes: [{ accessor: 'byScopeName', algorithm: 'btree', columns: ['scopeId', 'name'] }] },
  {
    id: t.u64().primaryKey().autoInc(),
    scopeId: t.u64().index('btree'),
    name: t.string(),
    permissions: t.array(t.string()),
    inherits: t.array(t.u64()),
    /** `permissions` plus everything inherited, flattened. Maintained by the module. */
    effective: t.array(t.string()),
    /** Defined by module code (clients can't change or delete it). */
    system: t.bool(),
  }
);

/** The scope tree. `path` lists the ancestors, root first (not 0, not the scope itself). */
const scopes = table(
  { name: 'scopes', public: true },
  {
    id: t.u64().primaryKey().autoInc(),
    parent: t.u64().index('btree'),
    kind: t.string(),
    name: t.string(),
    path: t.array(t.u64()),
    createdBy: t.option(t.identity()),
    createdAt: t.timestamp(),
  }
);

const grants = table(
  { name: 'grants', public: true, indexes: [{ accessor: 'byIdentityScope', algorithm: 'btree', columns: ['identity', 'scopeId'] }] },
  {
    id: t.u64().primaryKey().autoInc(),
    identity: t.identity().index('btree'),
    roleId: t.u64().index('btree'),
    scopeId: t.u64().index('btree'),
    /** undefined when module code granted it. */
    grantedBy: t.option(t.identity()),
    grantedAt: t.timestamp(),
    expiresAt: t.option(t.timestamp()),
  }
);

/** Invite metadata (the code itself is private, in `invite_codes`). */
const invites = table(
  { name: 'invites', public: true },
  {
    id: t.u64().primaryKey().autoInc(),
    roleId: t.u64(),
    scopeId: t.u64().index('btree'),
    createdBy: t.identity(),
    createdAt: t.timestamp(),
    expiresAt: t.option(t.timestamp()),
    /** 0 = unlimited. */
    maxUses: t.u32(),
    uses: t.u32(),
    /** Grants made from this invite expire after this many seconds (0 = never). */
    grantTtlSecs: t.u64(),
  }
);

const inviteCodes = table({ name: 'invite_codes' }, { code: t.string().primaryKey(), inviteId: t.u64().unique() });

/**
 * Who holds which watched permission where, expanded down the scope tree: the join target for
 * row-level security. Public with no RLS of its own (SpacetimeDB 2.11 rejects RLS joins through a
 * table that has RLS), so it reveals who can see what.
 */
const visible = table(
  { name: 'visible', public: true },
  {
    id: t.u64().primaryKey().autoInc(),
    identity: t.identity().index('btree'),
    scopeId: t.u64().index('btree'),
    perm: t.string(),
  }
);

/** Each identity's flattened permissions in every scope they reach, so a check is one lookup. */
const effective = table(
  { name: 'effective', indexes: [{ accessor: 'byIdentityScope', algorithm: 'btree', columns: ['identity', 'scopeId'] }] },
  {
    id: t.u64().primaryKey().autoInc(),
    identity: t.identity().index('btree'),
    scopeId: t.u64().index('btree'),
    perms: t.array(t.string()),
    /** The earliest expiry among the grants behind it; past it, checks take the slow path. */
    validUntil: t.option(t.timestamp()),
  }
);

const audit = table(
  { name: 'audit', public: true },
  {
    id: t.u64().primaryKey().autoInc(),
    at: t.timestamp(),
    /** undefined = module code or the scheduler. */
    actor: t.option(t.identity()),
    action: t.string(),
    /** Who the change was about; the zero identity when nobody in particular. */
    target: t.identity(),
    roleId: t.u64(),
    scopeId: t.u64().index('btree'),
    detail: t.string(),
  }
);

/** One-shot jobs: expire a grant (kind 0) or an invite (kind 1) on time. */
const jobs = table(
  { name: 'jobs' },
  { scheduledId: t.u64().primaryKey().autoInc(), scheduledAt: t.scheduleAt(), kind: t.u8(), target: t.u64() }
);

const spacetimedb = schema({ config, roles, scopes, grants, invites, inviteCodes, visible, effective, audit, jobs });
export default spacetimedb;

type S = typeof spacetimedb.schemaType;
/** A context narrowed to this submodule: pass `ctx.as.authz` (or whatever you named it). */
export type AuthzCtx = ReducerCtx<S>;
type Ctx = AuthzCtx;
type Role = NonNullable<ReturnType<Ctx['db']['roles']['id']['find']>>;
type Grant = NonNullable<ReturnType<Ctx['db']['grants']['id']['find']>>;

// ---------------------------------------------------------------------------
// Row-level security (the consumer declares these: submodules can't)
// ---------------------------------------------------------------------------

/**
 * The four rules this module needs, for the namespace you mounted it under:
 *
 * ```ts
 * const rls = authz.rlsSql('authz');
 * export const authzGrants = spacetimedb.clientVisibilityFilter.sql(rls.grants);
 * export const authzScopes = spacetimedb.clientVisibilityFilter.sql(rls.scopes);
 * export const authzInvites = spacetimedb.clientVisibilityFilter.sql(rls.invites);
 * export const authzAudit = spacetimedb.clientVisibilityFilter.sql(rls.audit);
 * ```
 *
 * One rule per table: SpacetimeDB 2.11 drops live updates from a join rule when the table has a
 * second rule.
 */
export function rlsSql(ns: string) {
  const v = `${ns}.visible`;
  const rule = (tbl: string, col: string, perm: string) =>
    `SELECT ${ns}.${tbl}.* FROM ${ns}.${tbl} JOIN ${v} ON ${ns}.${tbl}.${col} = ${v}.scope_id WHERE ${v}.identity = :sender AND ${v}.perm = '${perm}'`;
  return {
    /** Grants in scopes you're a member of (the roster). */
    grants: rule('grants', 'scope_id', MEMBER),
    /** Scopes you have any grant in (directly or through a parent). */
    scopes: rule('scopes', 'id', MEMBER),
    /** Invites in scopes where you can invite. */
    invites: rule('invites', 'scope_id', PERM_INVITE),
    /** Audit entries in scopes where you hold `authz.audit`. */
    audit: rule('audit', 'scope_id', PERM_AUDIT),
  };
}

/**
 * A rule that shows rows of your `table` to clients holding `perm` in the row's scope (`column`,
 * snake_case), including through parent scopes and global grants. Add `perm` to `watch`.
 */
export function rlsFor(table: string, column: string, perm: string, ns = 'authz'): string {
  const v = `${ns}.visible`;
  return `SELECT ${table}.* FROM ${table} JOIN ${v} ON ${table}.${column} = ${v}.scope_id WHERE ${v}.identity = :sender AND ${v}.perm = '${perm}'`;
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/** Does a held permission cover a requested one? `*` covers everything; `doc.*` covers `doc.x`, `doc.x.y`, `doc.*`. */
export function covers(held: string, wanted: string): boolean {
  if (held === '*' || held === wanted) return true;
  if (!held.endsWith('.*')) return false;
  const prefix = held.slice(0, -2);
  return wanted.length > prefix.length + 1 && wanted.startsWith(prefix) && wanted[prefix.length] === '.';
}

const us = (t: Timestamp) => t.microsSinceUnixEpoch;
const live = (g: Grant, now: Timestamp) => !g.expiresAt || us(g.expiresAt) > us(now);
const earliest = (a: Timestamp | undefined, b: Timestamp | undefined) => (a && b ? (us(a) <= us(b) ? a : b) : a ?? b);

/** The scope and all its ancestors, nearest first, ending with GLOBAL; undefined if unknown. */
function lineage(ctx: Ctx, scopeId: bigint): bigint[] | undefined {
  if (scopeId === GLOBAL) return [GLOBAL];
  const s = ctx.db.scopes.id.find(scopeId);
  if (!s) return undefined;
  return [scopeId, ...[...s.path].reverse(), GLOBAL];
}

/** Can `who` do `perm` in `scopeId`? One lookup in the precomputed `effective` table. */
export function can(ctx: Ctx, who: Identity, perm: string, scopeId: bigint): boolean {
  return permissions(ctx, who, scopeId).some((p) => covers(p, perm));
}

/** `can` for the caller; throws `permission denied: <perm>`. */
export function require(ctx: Ctx, perm: string, scopeId: bigint): void {
  if (!can(ctx, ctx.sender, perm, scopeId)) throw new SenderError(`permission denied: ${perm}`);
}

/** Every permission `who` holds in `scopeId` (directly or inherited), deduplicated. */
export function permissions(ctx: Ctx, who: Identity, scopeId: bigint): string[] {
  for (const e of ctx.db.effective.byIdentityScope.filter([who, scopeId])) {
    if (!e.validUntil || us(e.validUntil) > us(ctx.timestamp)) return e.perms;
    // A grant behind the cached row just expired and the expiry job hasn't run yet.
    return compute(ctx, who, scopeId).perms;
  }
  return []; // no row: no live grant reaches this scope
}

/** The slow path: walk the scope's lineage and the live grants on it. */
function compute(ctx: Ctx, who: Identity, scopeId: bigint): { perms: string[]; until?: Timestamp } {
  const out = new Set<string>();
  let until: Timestamp | undefined;
  for (const s of lineage(ctx, scopeId) ?? []) {
    for (const g of ctx.db.grants.byIdentityScope.filter([who, s])) {
      const role = live(g, ctx.timestamp) ? ctx.db.roles.id.find(g.roleId) : undefined;
      if (!role) continue;
      for (const p of role.effective) out.add(p);
      until = earliest(until, g.expiresAt);
    }
  }
  return { perms: [...out].sort(), until };
}

function holdsAll(ctx: Ctx, who: Identity, perms: string[], scopeId: bigint): boolean {
  const mine = permissions(ctx, who, scopeId);
  return perms.every((p) => mine.some((h) => covers(h, p)));
}

const roleUsableIn = (ctx: Ctx, role: Role, scopeId: bigint) =>
  role.scopeId === GLOBAL || (lineage(ctx, scopeId)?.includes(role.scopeId) ?? false);

function checkDelegate(ctx: Ctx, meta: string, roleId: bigint, scopeId: bigint): Role {
  require(ctx, meta, scopeId);
  const role = ctx.db.roles.id.find(roleId);
  if (!role) throw new SenderError('no such role');
  if (!roleUsableIn(ctx, role, scopeId)) throw new SenderError("that role isn't available in this scope");
  if (!holdsAll(ctx, ctx.sender, role.effective, scopeId)) throw new SenderError('you can only hand out roles whose permissions you hold');
  return role;
}

// ---------------------------------------------------------------------------
// Library API: call these from your own reducers with `ctx.as.authz` (no permission checks)
// ---------------------------------------------------------------------------

/** Store settings (from init). Call `refreshAll` after changing `watch` on a live database. */
export function configure(ctx: Ctx, settings: Settings): void {
  const row = { key: 0, settings };
  if (ctx.db.config.key.find(0)) ctx.db.config.key.update(row);
  else ctx.db.config.insert(row);
}

export function settings(ctx: Ctx): Settings {
  return ctx.db.config.key.find(0)?.settings ?? { watch: [], clientsDeleteScopes: false };
}

/** `scopeId` and every scope below it. */
export function subtree(ctx: Ctx, scopeId: bigint): bigint[] {
  const out = [scopeId];
  for (let i = 0; i < out.length; i++) for (const c of ctx.db.scopes.parent.filter(out[i])) out.push(c.id);
  return out;
}

/** A role's id by scope and name. */
export function findRole(ctx: Ctx, scopeId: bigint, name: string): bigint | undefined {
  for (const r of ctx.db.roles.byScopeName.filter([scopeId, name])) return r.id;
  return undefined;
}

/** Create the system role `owner` (`*`) if needed and grant it globally to `who`. */
export function bootstrap(ctx: Ctx, who: Identity): bigint {
  const owner = findRole(ctx, GLOBAL, 'owner') ?? newRole(ctx, GLOBAL, 'owner', ['*'], []);
  return addGrant(ctx, who, owner, GLOBAL, undefined, undefined);
}

/** Define a system role (clients can't change or delete it). Returns its id. */
export function newRole(ctx: Ctx, scopeId: bigint, name: string, perms: string[], inherits: bigint[]): bigint {
  return insertRole(ctx, scopeId, name, perms, inherits, true, undefined);
}

/** Create a scope under `parent` (0 = top level). Returns its id. */
export function newScope(ctx: Ctx, parent: bigint, kind: string, name: string, createdBy: Identity | undefined): bigint {
  checkName(name);
  checkName(kind);
  let path: bigint[] = [];
  if (parent !== GLOBAL) {
    const p = ctx.db.scopes.id.find(parent);
    if (!p) throw new SenderError('no such parent scope');
    path = [...p.path, p.id];
  }
  const s = ctx.db.scopes.insert({ id: 0n, parent, kind, name, path, createdBy, createdAt: ctx.timestamp });
  log(ctx, createdBy, 'scope.create', undefined, 0n, s.id, name);
  // People with grants on the ancestors (or global ones) now reach the new scope too.
  const watch = watched(ctx);
  for (const who of holdersAbove(ctx, s.id)) {
    const { perms, until } = compute(ctx, who, s.id);
    ctx.db.effective.insert({ id: 0n, identity: who, scopeId: s.id, perms, validUntil: until });
    for (const w of watch) {
      if (w === '' || perms.some((h) => covers(h, w))) ctx.db.visible.insert({ id: 0n, identity: who, scopeId: s.id, perm: w });
    }
  }
  return s.id;
}

/** Delete a scope, its subtree, and every grant, invite and scoped role in it. Delete your own rows first. */
export function removeScope(ctx: Ctx, scopeId: bigint, by: Identity | undefined): void {
  const root = ctx.db.scopes.id.find(scopeId);
  if (!root) throw new SenderError('no such scope');
  const affected = new Map<string, Identity>();
  for (const s of subtree(ctx, scopeId)) {
    for (const g of [...ctx.db.grants.scopeId.filter(s)]) {
      affected.set(g.identity.toHexString(), g.identity);
      ctx.db.grants.id.delete(g.id);
    }
    for (const inv of [...ctx.db.invites.scopeId.filter(s)]) deleteInvite(ctx, inv.id);
    for (const r of [...ctx.db.roles.scopeId.filter(s)]) ctx.db.roles.id.delete(r.id);
    ctx.db.scopes.id.delete(s);
    for (const e of [...ctx.db.effective.scopeId.filter(s)]) affected.set(e.identity.toHexString(), e.identity);
  }
  log(ctx, by, 'scope.delete', undefined, 0n, root.parent, root.name);
  for (const who of affected.values()) refresh(ctx, who);
}

/** Grant `roleId` to `who` in `scopeId`, optionally until `expiresAt`. Reuses an identical grant. */
export function addGrant(ctx: Ctx, who: Identity, roleId: bigint, scopeId: bigint, expiresAt: Timestamp | undefined, by: Identity | undefined): bigint {
  const role = ctx.db.roles.id.find(roleId);
  if (!role) throw new SenderError('no such role');
  if (scopeId !== GLOBAL && !ctx.db.scopes.id.find(scopeId)) throw new SenderError('no such scope');
  if (!roleUsableIn(ctx, role, scopeId)) throw new SenderError("that role isn't available in this scope");
  if (expiresAt && us(expiresAt) <= us(ctx.timestamp)) throw new SenderError('expiry is in the past');
  const existing = [...ctx.db.grants.byIdentityScope.filter([who, scopeId])].find((g) => g.roleId === roleId);
  let id: bigint;
  if (existing) {
    const later = existing.expiresAt && expiresAt ? (us(existing.expiresAt) >= us(expiresAt) ? existing.expiresAt : expiresAt) : undefined;
    ctx.db.grants.id.update({ ...existing, expiresAt: later });
    id = existing.id;
  } else {
    id = ctx.db.grants.insert({ id: 0n, identity: who, roleId, scopeId, grantedBy: by, grantedAt: ctx.timestamp, expiresAt }).id;
  }
  if (expiresAt) ctx.db.jobs.insert({ scheduledId: 0n, scheduledAt: ScheduleAt.time(us(expiresAt)), kind: 0, target: id });
  log(ctx, by, 'grant', who, roleId, scopeId, role.name);
  refresh(ctx, who);
  return id;
}

/** Remove a grant. */
export function removeGrant(ctx: Ctx, grantId: bigint, by: Identity | undefined): void {
  const g = ctx.db.grants.id.find(grantId);
  if (!g) throw new SenderError('no such grant');
  ctx.db.grants.id.delete(grantId);
  log(ctx, by, 'revoke', g.identity, g.roleId, g.scopeId, '');
  refresh(ctx, g.identity);
}

/** Recompute `effective` and `visible` for everyone (after changing watched permissions). */
export function refreshAll(ctx: Ctx): void {
  const people = new Map<string, Identity>();
  for (const g of ctx.db.grants.iter()) people.set(g.identity.toHexString(), g.identity);
  for (const e of ctx.db.effective.iter()) people.set(e.identity.toHexString(), e.identity);
  for (const who of people.values()) refresh(ctx, who);
}

// ---------------------------------------------------------------------------
// Client reducers (registered under the namespace: `authz.grant_role`, ...)
// ---------------------------------------------------------------------------

export const create_scope = spacetimedb.reducer({ parent: t.u64(), kind: t.string(), name: t.string() }, (ctx, { parent, kind, name }) => {
  require(ctx, PERM_SCOPE_CREATE, parent);
  newScope(ctx, parent, kind, name, ctx.sender);
});

export const delete_scope = spacetimedb.reducer({ scopeId: t.u64() }, (ctx, { scopeId }) => {
  if (scopeId === GLOBAL) throw new SenderError("can't delete the global scope");
  if (!settings(ctx).clientsDeleteScopes) throw new SenderError("scopes are deleted through this module's own reducers");
  require(ctx, PERM_SCOPE_DELETE, scopeId);
  removeScope(ctx, scopeId, ctx.sender);
});

export const grant_role = spacetimedb.reducer(
  { identity: t.identity(), roleId: t.u64(), scopeId: t.u64(), expiresAt: t.option(t.timestamp()) },
  (ctx, { identity, roleId, scopeId, expiresAt }) => {
    checkDelegate(ctx, PERM_GRANT, roleId, scopeId);
    addGrant(ctx, identity, roleId, scopeId, expiresAt, ctx.sender);
  }
);

/** Revoke a grant: your own (leaving), or one you could have granted. */
export const revoke_grant = spacetimedb.reducer({ grantId: t.u64() }, (ctx, { grantId }) => {
  const g = ctx.db.grants.id.find(grantId);
  if (!g) throw new SenderError('no such grant');
  if (!g.identity.isEqual(ctx.sender)) checkDelegate(ctx, PERM_GRANT, g.roleId, g.scopeId);
  removeGrant(ctx, grantId, ctx.sender);
});

export const create_role = spacetimedb.reducer(
  { scopeId: t.u64(), name: t.string(), permissions: t.array(t.string()), inherits: t.array(t.u64()) },
  (ctx, { scopeId, name, permissions: perms, inherits }) => {
    require(ctx, PERM_ROLE, scopeId);
    insertRole(ctx, scopeId, name, perms, inherits, false, ctx.sender);
  }
);

/** Change a non-system role. You must hold its old and new permissions in its scope. */
export const update_role = spacetimedb.reducer(
  { roleId: t.u64(), permissions: t.array(t.string()), inherits: t.array(t.u64()) },
  (ctx, { roleId, permissions: perms, inherits }) => {
    const role = ctx.db.roles.id.find(roleId);
    if (!role) throw new SenderError('no such role');
    if (role.system) throw new SenderError('system roles can only be changed by the module');
    require(ctx, PERM_ROLE, role.scopeId);
    if (!holdsAll(ctx, ctx.sender, role.effective, role.scopeId)) throw new SenderError('you can only change roles whose permissions you hold');
    checkPerms(perms);
    checkInherits(ctx, role.scopeId, inherits, roleId);
    const eff = flatten(ctx, perms, inherits);
    if (!holdsAll(ctx, ctx.sender, eff, role.scopeId)) throw new SenderError('you can only give a role permissions you hold');
    ctx.db.roles.id.update({ ...role, permissions: perms, inherits });
    recomputeRoles(ctx);
    log(ctx, ctx.sender, 'role.update', undefined, roleId, role.scopeId, role.name);
  }
);

/** Delete a non-system role nobody holds or inherits. */
export const delete_role = spacetimedb.reducer({ roleId: t.u64() }, (ctx, { roleId }) => {
  const role = ctx.db.roles.id.find(roleId);
  if (!role) throw new SenderError('no such role');
  if (role.system) throw new SenderError('system roles can only be deleted by the module');
  require(ctx, PERM_ROLE, role.scopeId);
  if (!holdsAll(ctx, ctx.sender, role.effective, role.scopeId)) throw new SenderError('you can only delete roles whose permissions you hold');
  if (!ctx.db.grants.roleId.filter(roleId).next().done) throw new SenderError('role is still granted');
  if ([...ctx.db.roles.iter()].some((r) => r.inherits.includes(roleId))) throw new SenderError('another role inherits it');
  for (const inv of [...ctx.db.invites.iter()].filter((i) => i.roleId === roleId)) deleteInvite(ctx, inv.id);
  ctx.db.roles.id.delete(roleId);
  log(ctx, ctx.sender, 'role.delete', undefined, roleId, role.scopeId, role.name);
});

/** Create an invite. Generate the code on the client (16+ random characters) and share it. */
export const create_invite = spacetimedb.reducer(
  { code: t.string(), roleId: t.u64(), scopeId: t.u64(), maxUses: t.u32(), expiresAt: t.option(t.timestamp()), grantTtlSecs: t.u64() },
  (ctx, { code, roleId, scopeId, maxUses, expiresAt, grantTtlSecs }) => {
    checkDelegate(ctx, PERM_INVITE, roleId, scopeId);
    if (code.length < MIN_INVITE_CODE || code.length > 128) throw new SenderError(`invite codes must be ${MIN_INVITE_CODE}-128 characters`);
    if (ctx.db.inviteCodes.code.find(code)) throw new SenderError('that code is taken');
    if (expiresAt && us(expiresAt) <= us(ctx.timestamp)) throw new SenderError('expiry is in the past');
    const inv = ctx.db.invites.insert({ id: 0n, roleId, scopeId, createdBy: ctx.sender, createdAt: ctx.timestamp, expiresAt, maxUses, uses: 0, grantTtlSecs });
    ctx.db.inviteCodes.insert({ code, inviteId: inv.id });
    if (expiresAt) ctx.db.jobs.insert({ scheduledId: 0n, scheduledAt: ScheduleAt.time(us(expiresAt)), kind: 1, target: inv.id });
    log(ctx, ctx.sender, 'invite.create', undefined, roleId, scopeId, '');
  }
);

export const revoke_invite = spacetimedb.reducer({ inviteId: t.u64() }, (ctx, { inviteId }) => {
  const inv = ctx.db.invites.id.find(inviteId);
  if (!inv) throw new SenderError('no such invite');
  if (!inv.createdBy.isEqual(ctx.sender)) checkDelegate(ctx, PERM_INVITE, inv.roleId, inv.scopeId);
  deleteInvite(ctx, inviteId);
  log(ctx, ctx.sender, 'invite.revoke', undefined, inv.roleId, inv.scopeId, '');
});

/** Redeem an invite code. The inviter must still be allowed to hand out the role. */
export const redeem_invite = spacetimedb.reducer({ code: t.string() }, (ctx, { code }) => {
  const link = ctx.db.inviteCodes.code.find(code);
  const inv = link && ctx.db.invites.id.find(link.inviteId);
  if (!inv) throw new SenderError('invalid invite');
  // (Deleting an expired invite here would be rolled back with the error; the job removes it.)
  if (inv.expiresAt && us(inv.expiresAt) <= us(ctx.timestamp)) throw new SenderError('invite expired');
  const role = ctx.db.roles.id.find(inv.roleId);
  if (!role) throw new SenderError('invalid invite');
  if (!can(ctx, inv.createdBy, PERM_INVITE, inv.scopeId) || !holdsAll(ctx, inv.createdBy, role.effective, inv.scopeId)) {
    throw new SenderError('the inviter can no longer grant this role');
  }
  const expiresAt = inv.grantTtlSecs > 0n ? new Timestamp(us(ctx.timestamp) + inv.grantTtlSecs * 1_000_000n) : undefined;
  addGrant(ctx, ctx.sender, inv.roleId, inv.scopeId, expiresAt, inv.createdBy);
  const uses = inv.uses + 1;
  log(ctx, ctx.sender, 'invite.redeem', ctx.sender, inv.roleId, inv.scopeId, '');
  if (inv.maxUses > 0 && uses >= inv.maxUses) deleteInvite(ctx, inv.id);
  else ctx.db.invites.id.update({ ...inv, uses });
});

/** Scheduled: expire a grant or invite on time. Not callable by clients. */
export const run_job = spacetimedb.reducer({ onSchedule: jobs }, { arg: jobs.rowType }, (ctx, { arg }) => {
  if (!ctx.sender.isEqual(ctx.databaseIdentity)) throw new SenderError('scheduler only');
  if (arg.kind === 0) {
    const g = ctx.db.grants.id.find(arg.target);
    if (g && !live(g, ctx.timestamp)) {
      ctx.db.grants.id.delete(g.id);
      log(ctx, undefined, 'expire', g.identity, g.roleId, g.scopeId, '');
      refresh(ctx, g.identity);
    }
  } else {
    const inv = ctx.db.invites.id.find(arg.target);
    if (inv?.expiresAt && us(inv.expiresAt) <= us(ctx.timestamp)) {
      deleteInvite(ctx, inv.id);
      log(ctx, undefined, 'invite.expire', undefined, inv.roleId, inv.scopeId, '');
    }
  }
});

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function checkName(s: string) {
  if (s.trim().length === 0 || [...s].length > MAX_NAME) throw new SenderError(`names must be 1-${MAX_NAME} characters`);
}

function checkPerms(perms: string[]) {
  if (perms.length > MAX_PERMS) throw new SenderError(`at most ${MAX_PERMS} permissions per role`);
  for (const p of perms) {
    const ok =
      p.length > 0 &&
      p.length <= 128 &&
      /^[A-Za-z0-9._*-]+$/.test(p) &&
      (p === '*' || !p.includes('*') || (p.endsWith('.*') && !p.slice(0, -2).includes('*')));
    if (!ok) throw new SenderError(`bad permission \`${p}\`: use a.b.c, a.*, or *`);
  }
}

/** Inherited roles must exist, be usable in `scopeId`, and not form a cycle. */
function checkInherits(ctx: Ctx, scopeId: bigint, inherits: bigint[], self: bigint | undefined) {
  for (const id of inherits) {
    const r = ctx.db.roles.id.find(id);
    if (!r) throw new SenderError("inherited role doesn't exist");
    if (!roleUsableIn(ctx, r, scopeId)) throw new SenderError("inherited role isn't available in this scope");
  }
  if (self === undefined) return;
  const stack = [...inherits];
  const seen = new Set<bigint>();
  while (stack.length) {
    const id = stack.pop()!;
    if (id === self) throw new SenderError("roles can't inherit themselves");
    const r = !seen.has(id) && ctx.db.roles.id.find(id);
    seen.add(id);
    if (r) stack.push(...r.inherits);
  }
}

function flatten(ctx: Ctx, perms: string[], inherits: bigint[]): string[] {
  const out = new Set(perms);
  const stack = [...inherits];
  const seen = new Set<bigint>();
  while (stack.length) {
    const id = stack.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const r = ctx.db.roles.id.find(id);
    if (!r) continue;
    for (const p of r.permissions) out.add(p);
    stack.push(...r.inherits);
  }
  return [...out].sort();
}

function insertRole(ctx: Ctx, scopeId: bigint, name: string, perms: string[], inherits: bigint[], system: boolean, by: Identity | undefined): bigint {
  checkName(name);
  checkPerms(perms);
  if (scopeId !== GLOBAL && !ctx.db.scopes.id.find(scopeId)) throw new SenderError('no such scope');
  if (findRole(ctx, scopeId, name) !== undefined) throw new SenderError('a role with that name exists in this scope');
  checkInherits(ctx, scopeId, inherits, undefined);
  const eff = flatten(ctx, perms, inherits);
  if (by && !holdsAll(ctx, by, eff, scopeId)) throw new SenderError('you can only give a role permissions you hold');
  const r = ctx.db.roles.insert({ id: 0n, scopeId, name, permissions: perms, inherits, effective: eff, system });
  log(ctx, by, 'role.create', undefined, r.id, scopeId, name);
  return r.id;
}

/** Re-flatten every role (roles are few), then refresh everyone whose permissions changed. */
function recomputeRoles(ctx: Ctx) {
  const changed: bigint[] = [];
  for (const r of [...ctx.db.roles.iter()]) {
    const eff = flatten(ctx, r.permissions, r.inherits);
    if (eff.join('\n') !== r.effective.join('\n')) {
      changed.push(r.id);
      ctx.db.roles.id.update({ ...r, effective: eff });
    }
  }
  const people = new Map<string, Identity>();
  for (const id of changed) for (const g of ctx.db.grants.roleId.filter(id)) people.set(g.identity.toHexString(), g.identity);
  for (const who of people.values()) refresh(ctx, who);
}

function deleteInvite(ctx: Ctx, inviteId: bigint) {
  ctx.db.invites.id.delete(inviteId);
  ctx.db.inviteCodes.inviteId.delete(inviteId);
}

/** Everyone with a live grant on `scopeId`'s ancestors, including global ones. */
function holdersAbove(ctx: Ctx, scopeId: bigint): Identity[] {
  const out = new Map<string, Identity>();
  for (const s of (lineage(ctx, scopeId) ?? []).slice(1)) {
    for (const g of ctx.db.grants.scopeId.filter(s)) if (live(g, ctx.timestamp)) out.set(g.identity.toHexString(), g.identity);
  }
  return [...out.values()];
}

function watched(ctx: Ctx): string[] {
  const w = [MEMBER, PERM_GRANT, PERM_INVITE, PERM_AUDIT];
  for (const p of settings(ctx).watch) if (!w.includes(p)) w.push(p);
  return w;
}

/**
 * Rebuild `who`'s rows in `effective` and `visible`: their flattened permissions in every scope
 * they reach, and for each watched permission every scope where they hold it. Grants expand down
 * the tree; a global grant expands to every scope.
 */
function refresh(ctx: Ctx, who: Identity) {
  const eff = new Map<bigint, { perms: Set<string>; until?: Timestamp }>();
  const children = new Map<bigint, bigint[]>();
  for (const g of ctx.db.grants.identity.filter(who)) {
    const role = live(g, ctx.timestamp) ? ctx.db.roles.id.find(g.roleId) : undefined;
    if (!role) continue;
    const reach = [g.scopeId];
    for (let i = 0; i < reach.length; i++) {
      let kids = children.get(reach[i]);
      if (!kids) children.set(reach[i], (kids = [...ctx.db.scopes.parent.filter(reach[i])].map((c) => c.id)));
      reach.push(...kids);
    }
    for (const s of reach) {
      const e = eff.get(s) ?? { perms: new Set<string>() };
      for (const p of role.effective) e.perms.add(p);
      e.until = earliest(e.until, g.expiresAt);
      eff.set(s, e);
    }
  }

  // effective: one row per reached scope.
  const old = new Map([...ctx.db.effective.identity.filter(who)].map((e) => [e.scopeId, e]));
  for (const [scopeId, e] of eff) {
    const perms = [...e.perms].sort();
    const row = old.get(scopeId);
    old.delete(scopeId);
    if (!row) ctx.db.effective.insert({ id: 0n, identity: who, scopeId, perms, validUntil: e.until });
    else if (row.perms.join('\n') !== perms.join('\n') || row.validUntil?.microsSinceUnixEpoch !== e.until?.microsSinceUnixEpoch) {
      ctx.db.effective.id.update({ ...row, perms, validUntil: e.until });
    }
  }
  for (const row of old.values()) ctx.db.effective.id.delete(row.id);

  // visible: (scope, watched permission) pairs.
  const watch = watched(ctx);
  const want = new Set<string>();
  for (const [scopeId, e] of eff) {
    for (const w of watch) if (w === '' || [...e.perms].some((h) => covers(h, w))) want.add(`${scopeId}\n${w}`);
  }
  for (const row of [...ctx.db.visible.identity.filter(who)]) {
    if (!want.delete(`${row.scopeId}\n${row.perm}`)) ctx.db.visible.id.delete(row.id);
  }
  for (const key of want) {
    const [scopeId, perm] = key.split('\n');
    ctx.db.visible.insert({ id: 0n, identity: who, scopeId: BigInt(scopeId), perm: perm ?? '' });
  }
}

function log(ctx: Ctx, actor: Identity | undefined, action: string, target: Identity | undefined, roleId: bigint, scopeId: bigint, detail: string) {
  ctx.db.audit.insert({ id: 0n, at: ctx.timestamp, actor, action, target: target ?? Identity.zero(), roleId, scopeId, detail });
}
