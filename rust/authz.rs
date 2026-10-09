//! # authz.rs: roles, scopes and grants for SpacetimeDB, one drop-in file
//!
//! Copy this file to your module's `src/authz.rs`, add `pub mod authz;` to `lib.rs`, enable the
//! `unstable` feature on the `spacetimedb` crate (the row-level-security rules need it), and set
//! it up from `init`:
//!
//! ```ignore
//! #[spacetimedb::reducer(init)]
//! pub fn init(ctx: &ReducerContext) -> Result<(), String> {
//!     authz::configure(ctx, authz::AuthzSettings { watch: vec!["doc.read".into()] });
//!     authz::bootstrap(ctx, ctx.sender())?;          // the publisher gets `owner` (`*`) everywhere
//!     let viewer = authz::create_role(ctx, 0, "viewer", &["doc.read"], &[])?;
//!     authz::create_role(ctx, 0, "editor", &["doc.write"], &[viewer])?;
//!     Ok(())
//! }
//!
//! #[spacetimedb::reducer]
//! pub fn edit_doc(ctx: &ReducerContext, id: u64, body: String) -> Result<(), String> {
//!     let doc = ctx.db.doc().id().find(id).ok_or("no such doc")?;
//!     authz::require(ctx, "doc.write", doc.scope_id)?;
//!     // ...
//! }
//! ```
//!
//! What it gives you:
//!
//! - **Roles** hold permission strings (`doc.write`, wildcards like `doc.*`, or `*`) and can
//!   inherit other roles. A role's flattened permission set is cached on the row.
//! - **Scopes** form a tree (workspace → project → …). A grant on a scope applies to everything
//!   below it. Scope `0` is global.
//! - **Grants** give an identity a role in a scope, optionally until an exact expiry (a one-shot
//!   schedule removes it on time).
//! - **Invites**: a code that grants a role on redemption, with a use limit and expiry.
//! - **No privilege escalation**: clients can only grant, revoke, invite or define roles whose
//!   permissions they hold themselves, in scopes where they hold the matching `authz.*` permission.
//! - **Audit log** of every change, and **row-level security**: clients see the scopes they're in
//!   and their rosters, invites where they can invite, and the audit log where they hold `authz.audit`.
//! - **RLS for your tables**: `authz_visible` lists who holds which *watched* permission where, so
//!   one join gates any table that has a scope column (see [`authz_rls!`]).

use spacetimedb::{
    Filter, Identity, ReducerContext, ScheduleAt, SpacetimeType, Table, Timestamp,
    client_visibility_filter,
};
use std::collections::{BTreeSet, HashMap, HashSet};

// ---------------------------------------------------------------------------
// Permissions this module checks itself
// ---------------------------------------------------------------------------

/// Grant and revoke roles in a scope (only roles whose permissions you hold).
pub const PERM_GRANT: &str = "authz.grant";
/// Create and revoke invites in a scope (same rule as granting).
pub const PERM_INVITE: &str = "authz.invite";
/// Define, change and delete roles in a scope (only with permissions you hold).
pub const PERM_ROLE: &str = "authz.role";
/// Create child scopes.
pub const PERM_SCOPE_CREATE: &str = "authz.scope.create";
/// Delete a scope and everything under it.
pub const PERM_SCOPE_DELETE: &str = "authz.scope.delete";
/// See the audit log of a scope (row-level security).
pub const PERM_AUDIT: &str = "authz.audit";
/// The `perm` value in `authz_visible` meaning "has any grant reaching this scope".
pub const MEMBER: &str = "";
/// The global scope.
pub const GLOBAL: u64 = 0;

const MAX_NAME: usize = 64;
const MAX_PERMS: usize = 64;
const MIN_INVITE_CODE: usize = 16;

/// Tunables.
#[derive(SpacetimeType, Clone, Debug, PartialEq, Default)]
pub struct AuthzSettings {
    /// Permissions to materialise in `authz_visible` for your own RLS rules (e.g. `doc.read`).
    /// `authz.grant`, `authz.invite`, `authz.audit` and membership are always watched.
    pub watch: Vec<String>,
    /// Allow the `authz_delete_scope` reducer. Off by default: deleting a scope doesn't delete your
    /// own rows in it, so most modules want their own delete reducer that cleans up first.
    pub clients_delete_scopes: bool,
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

#[spacetimedb::table(accessor = authz_config)]
pub struct AuthzConfig {
    #[primary_key]
    pub key: u8,
    pub settings: AuthzSettings,
}

/// Roles. `scope_id` 0 = usable everywhere; otherwise only in that scope and below.
#[spacetimedb::table(
    accessor = authz_role,
    public,
    index(accessor = by_scope_name, btree(columns = [scope_id, name]))
)]
#[derive(Clone)]
pub struct AuthzRole {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    #[index(btree)]
    pub scope_id: u64,
    pub name: String,
    pub permissions: Vec<String>,
    pub inherits: Vec<u64>,
    /// `permissions` plus everything inherited, flattened. Maintained by the module.
    pub effective: Vec<String>,
    /// Defined by module code (clients can't change or delete it).
    pub system: bool,
}

/// The scope tree. `path` lists the ancestors, root first (not including 0 or the scope itself).
#[spacetimedb::table(accessor = authz_scope, public)]
#[derive(Clone)]
pub struct AuthzScope {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    #[index(btree)]
    pub parent: u64,
    pub kind: String,
    pub name: String,
    pub path: Vec<u64>,
    pub created_by: Option<Identity>,
    pub created_at: Timestamp,
}

#[spacetimedb::table(
    accessor = authz_grant,
    public,
    index(accessor = by_identity_scope, btree(columns = [identity, scope_id]))
)]
#[derive(Clone)]
pub struct AuthzGrant {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    #[index(btree)]
    pub identity: Identity,
    #[index(btree)]
    pub role_id: u64,
    #[index(btree)]
    pub scope_id: u64,
    /// `None` when module code granted it.
    pub granted_by: Option<Identity>,
    pub granted_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}

/// Invite metadata (the code itself is private, in `authz_invite_code`).
#[spacetimedb::table(accessor = authz_invite, public)]
#[derive(Clone)]
pub struct AuthzInvite {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    pub role_id: u64,
    #[index(btree)]
    pub scope_id: u64,
    pub created_by: Identity,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    /// 0 = unlimited.
    pub max_uses: u32,
    pub uses: u32,
    /// Grants made from this invite expire after this many seconds (0 = never).
    pub grant_ttl_secs: u64,
}

#[spacetimedb::table(accessor = authz_invite_code)]
pub struct AuthzInviteCode {
    #[primary_key]
    pub code: String,
    #[unique]
    pub invite_id: u64,
}

/// Who holds which watched permission where, expanded down the scope tree. The join target for
/// row-level security. It has to be public with no RLS of its own (SpacetimeDB 2.11 rejects RLS
/// joins through a table that has RLS), so it reveals who can see what.
#[spacetimedb::table(accessor = authz_visible, public)]
pub struct AuthzVisible {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    #[index(btree)]
    pub identity: Identity,
    #[index(btree)]
    pub scope_id: u64,
    pub perm: String,
}

/// Each identity's flattened permissions in every scope they reach (grants inherited down the
/// tree, roles flattened), so a check is one index lookup. Rebuilt with `authz_visible`. Private.
#[spacetimedb::table(
    accessor = authz_effective,
    index(accessor = by_identity_scope, btree(columns = [identity, scope_id]))
)]
pub struct AuthzEffective {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    #[index(btree)]
    pub identity: Identity,
    #[index(btree)]
    pub scope_id: u64,
    pub perms: Vec<String>,
    /// The earliest expiry among the grants behind it; past it, checks take the slow path.
    pub valid_until: Option<Timestamp>,
}

#[spacetimedb::table(accessor = authz_audit, public)]
pub struct AuthzAudit {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    pub at: Timestamp,
    /// `None` = module code or the scheduler.
    pub actor: Option<Identity>,
    pub action: String,
    /// Who the change was about; `Identity::ZERO` when nobody in particular. (Not an `Option`:
    /// RLS can't compare an optional column with `:sender`, should you add a rule for it.)
    pub target: Identity,
    pub role_id: u64,
    #[index(btree)]
    pub scope_id: u64,
    pub detail: String,
}

/// One-shot jobs: expire a grant or an invite at its exact expiry time.
#[spacetimedb::table(accessor = authz_job, scheduled(authz_run_job))]
pub struct AuthzJob {
    #[primary_key]
    #[auto_inc]
    pub scheduled_id: u64,
    pub scheduled_at: ScheduleAt,
    /// 0 = grant, 1 = invite.
    pub kind: u8,
    pub target: u64,
}

// ---------------------------------------------------------------------------
// Row-level security
// ---------------------------------------------------------------------------

// One rule per table: SpacetimeDB 2.11 drops live updates from a join rule when the table has a
// second rule (the initial subscription is right, later inserts never arrive). See FINDINGS.

/// Grants in scopes you're a member of (the roster).
#[client_visibility_filter]
const AUTHZ_GRANT_MEMBER: Filter = Filter::Sql(
    "SELECT authz_grant.* FROM authz_grant JOIN authz_visible ON authz_grant.scope_id = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = ''",
);
/// Scopes you have any grant in (directly or through a parent).
#[client_visibility_filter]
const AUTHZ_SCOPE_MEMBER: Filter = Filter::Sql(
    "SELECT authz_scope.* FROM authz_scope JOIN authz_visible ON authz_scope.id = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = ''",
);
/// Invites in scopes where you can invite.
#[client_visibility_filter]
const AUTHZ_INVITE_MANAGED: Filter = Filter::Sql(
    "SELECT authz_invite.* FROM authz_invite JOIN authz_visible ON authz_invite.scope_id = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = 'authz.invite'",
);
/// Audit entries in scopes where you hold `authz.audit`.
#[client_visibility_filter]
const AUTHZ_AUDIT_MANAGED: Filter = Filter::Sql(
    "SELECT authz_audit.* FROM authz_audit JOIN authz_visible ON authz_audit.scope_id = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = 'authz.audit'",
);

/// An RLS rule that shows rows of `$table` to clients holding `$perm` in the row's scope
/// (`$column`), including through parent scopes and global grants:
///
/// ```ignore
/// authz_rls!(DOC_READ, "doc", "scope_id", "doc.read");
/// ```
///
/// Add `$perm` to `AuthzSettings::watch`, and index `$column`. Join `authz_visible` only: joining
/// a table that has RLS of its own fails in SpacetimeDB 2.11.
#[macro_export]
macro_rules! authz_rls {
    ($name:ident, $table:literal, $column:literal, $perm:literal) => {
        #[spacetimedb::client_visibility_filter]
        const $name: spacetimedb::Filter = spacetimedb::Filter::Sql(concat!(
            "SELECT ", $table, ".* FROM ", $table, " JOIN authz_visible ON ", $table, ".", $column,
            " = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = '",
            $perm, "'"
        ));
    };
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// Does a held permission cover a requested one? `*` covers everything; `doc.*` covers `doc.x`,
/// `doc.x.y` and `doc.*`.
pub fn covers(held: &str, wanted: &str) -> bool {
    if held == "*" || held == wanted {
        return true;
    }
    match held.strip_suffix(".*") {
        Some(prefix) => {
            wanted.len() > prefix.len() + 1
                && wanted.starts_with(prefix)
                && wanted.as_bytes()[prefix.len()] == b'.'
        }
        None => false,
    }
}

fn live(g: &AuthzGrant, now: Timestamp) -> bool {
    g.expires_at.is_none_or(|t| t > now)
}

/// The scope and all its ancestors, nearest first, ending with GLOBAL.
fn lineage(ctx: &ReducerContext, scope_id: u64) -> Option<Vec<u64>> {
    if scope_id == GLOBAL {
        return Some(vec![GLOBAL]);
    }
    let s = ctx.db.authz_scope().id().find(scope_id)?;
    let mut out = vec![scope_id];
    out.extend(s.path.iter().rev());
    out.push(GLOBAL);
    Some(out)
}

/// Can `who` do `perm` in `scope_id`? One lookup in the precomputed `authz_effective`.
pub fn can(ctx: &ReducerContext, who: Identity, perm: &str, scope_id: u64) -> bool {
    permissions(ctx, who, scope_id)
        .iter()
        .any(|p| covers(p, perm))
}

/// `can` for the caller, as a `Result` for `?`.
pub fn require(ctx: &ReducerContext, perm: &str, scope_id: u64) -> Result<(), String> {
    if can(ctx, ctx.sender(), perm, scope_id) {
        Ok(())
    } else {
        Err(format!("permission denied: {perm}"))
    }
}

/// Every permission `who` holds in `scope_id` (directly or inherited), deduplicated.
pub fn permissions(ctx: &ReducerContext, who: Identity, scope_id: u64) -> Vec<String> {
    match ctx
        .db
        .authz_effective()
        .by_identity_scope()
        .filter((who, scope_id))
        .next()
    {
        Some(e) if e.valid_until.is_none_or(|t| t > ctx.timestamp) => e.perms,
        // A grant behind the cached row just expired and the expiry job hasn't run yet.
        Some(_) => compute(ctx, who, scope_id).0,
        // No row: no live grant reaches this scope.
        None => vec![],
    }
}

/// The slow path: walk the scope's lineage and the caller's live grants on it.
fn compute(ctx: &ReducerContext, who: Identity, scope_id: u64) -> (Vec<String>, Option<Timestamp>) {
    let mut out = BTreeSet::new();
    let mut until: Option<Timestamp> = None;
    for s in lineage(ctx, scope_id).unwrap_or_default() {
        for g in ctx.db.authz_grant().by_identity_scope().filter((who, s)) {
            if live(&g, ctx.timestamp)
                && let Some(role) = ctx.db.authz_role().id().find(g.role_id)
            {
                out.extend(role.effective);
                until = earliest(until, g.expires_at);
            }
        }
    }
    (out.into_iter().collect(), until)
}

fn earliest(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Timestamp> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// Can `who` hand out every permission in `perms` at `scope_id`?
fn holds_all(ctx: &ReducerContext, who: Identity, perms: &[String], scope_id: u64) -> bool {
    let mine = permissions(ctx, who, scope_id);
    perms.iter().all(|p| mine.iter().any(|h| covers(h, p)))
}

/// May the caller hand out (grant, revoke, invite) `role_id` at `scope_id` with `meta`?
fn check_delegate(
    ctx: &ReducerContext,
    meta: &str,
    role_id: u64,
    scope_id: u64,
) -> Result<AuthzRole, String> {
    require(ctx, meta, scope_id)?;
    let role = ctx
        .db
        .authz_role()
        .id()
        .find(role_id)
        .ok_or("no such role")?;
    if !role_usable_in(ctx, &role, scope_id) {
        return Err("that role isn't available in this scope".into());
    }
    if !holds_all(ctx, ctx.sender(), &role.effective, scope_id) {
        return Err("you can only hand out roles whose permissions you hold".into());
    }
    Ok(role)
}

fn role_usable_in(ctx: &ReducerContext, role: &AuthzRole, scope_id: u64) -> bool {
    role.scope_id == GLOBAL || lineage(ctx, scope_id).is_some_and(|l| l.contains(&role.scope_id))
}

// ---------------------------------------------------------------------------
// Library API: call these from your own reducers (no permission checks)
// ---------------------------------------------------------------------------

/// Store settings (call from `init`). Watched permissions take effect for later changes; call
/// [`refresh_all`] after changing them on a live database.
pub fn configure(ctx: &ReducerContext, settings: AuthzSettings) {
    let row = AuthzConfig { key: 0, settings };
    if ctx.db.authz_config().key().find(0).is_some() {
        ctx.db.authz_config().key().update(row);
    } else {
        ctx.db.authz_config().insert(row);
    }
}

pub fn settings(ctx: &ReducerContext) -> AuthzSettings {
    ctx.db
        .authz_config()
        .key()
        .find(0)
        .map(|c| c.settings)
        .unwrap_or_default()
}

/// `scope_id` and every scope below it.
pub fn subtree(ctx: &ReducerContext, scope_id: u64) -> Vec<u64> {
    let mut out = vec![scope_id];
    let mut i = 0;
    while i < out.len() {
        out.extend(ctx.db.authz_scope().parent().filter(out[i]).map(|c| c.id));
        i += 1;
    }
    out
}

/// A role's id by scope and name.
pub fn find_role(ctx: &ReducerContext, scope_id: u64, name: &str) -> Option<u64> {
    ctx.db
        .authz_role()
        .by_scope_name()
        .filter((scope_id, name))
        .next()
        .map(|r| r.id)
}

/// Create the system role `owner` (`*`) if needed and grant it globally to `who`.
pub fn bootstrap(ctx: &ReducerContext, who: Identity) -> Result<u64, String> {
    let owner = match ctx
        .db
        .authz_role()
        .by_scope_name()
        .filter((GLOBAL, "owner"))
        .next()
    {
        Some(r) => r.id,
        None => create_role(ctx, GLOBAL, "owner", &["*"], &[])?,
    };
    grant(ctx, who, owner, GLOBAL, None, None)
}

/// Define a system role (clients can't change or delete it). Returns its id.
pub fn create_role(
    ctx: &ReducerContext,
    scope_id: u64,
    name: &str,
    permissions: &[&str],
    inherits: &[u64],
) -> Result<u64, String> {
    let perms: Vec<String> = permissions.iter().map(|p| p.to_string()).collect();
    insert_role(ctx, scope_id, name, perms, inherits.to_vec(), true, None)
}

/// Create a scope under `parent` (0 = top level). Returns its id.
pub fn create_scope(
    ctx: &ReducerContext,
    parent: u64,
    kind: &str,
    name: &str,
    created_by: Option<Identity>,
) -> Result<u64, String> {
    check_name(name)?;
    check_name(kind)?;
    let path = if parent == GLOBAL {
        vec![]
    } else {
        let p = ctx
            .db
            .authz_scope()
            .id()
            .find(parent)
            .ok_or("no such parent scope")?;
        let mut path = p.path.clone();
        path.push(p.id);
        path
    };
    let s = ctx.db.authz_scope().insert(AuthzScope {
        id: 0,
        parent,
        kind: kind.to_string(),
        name: name.to_string(),
        path,
        created_by,
        created_at: ctx.timestamp,
    });
    audit(ctx, created_by, "scope.create", None, 0, s.id, name);
    // People with grants on the ancestors (or global ones) now reach the new scope too.
    let watch = watched(ctx);
    for who in holders_above(ctx, s.id) {
        let (held, valid_until) = compute(ctx, who, s.id);
        for p in watch
            .iter()
            .filter(|w| w.is_empty() || held.iter().any(|h| covers(h, w)))
        {
            ctx.db.authz_visible().insert(AuthzVisible {
                id: 0,
                identity: who,
                scope_id: s.id,
                perm: p.clone(),
            });
        }
        ctx.db.authz_effective().insert(AuthzEffective {
            id: 0,
            identity: who,
            scope_id: s.id,
            perms: held,
            valid_until,
        });
    }
    Ok(s.id)
}

/// Delete a scope, its subtree, and every grant, invite and scoped role in it. Delete your own
/// rows that point at these scopes first.
pub fn delete_scope(
    ctx: &ReducerContext,
    scope_id: u64,
    by: Option<Identity>,
) -> Result<(), String> {
    let root = ctx
        .db
        .authz_scope()
        .id()
        .find(scope_id)
        .ok_or("no such scope")?;
    let doomed = subtree(ctx, scope_id);
    let mut affected = HashSet::new();
    for &s in &doomed {
        for g in ctx
            .db
            .authz_grant()
            .scope_id()
            .filter(s)
            .collect::<Vec<_>>()
        {
            affected.insert(g.identity);
            ctx.db.authz_grant().id().delete(g.id);
        }
        for inv in ctx
            .db
            .authz_invite()
            .scope_id()
            .filter(s)
            .collect::<Vec<_>>()
        {
            delete_invite(ctx, inv.id);
        }
        for r in ctx.db.authz_role().scope_id().filter(s).collect::<Vec<_>>() {
            ctx.db.authz_role().id().delete(r.id);
        }
        ctx.db.authz_scope().id().delete(s);
    }
    for &s in &doomed {
        affected.extend(
            ctx.db
                .authz_effective()
                .scope_id()
                .filter(s)
                .map(|e| e.identity),
        );
    }
    audit(ctx, by, "scope.delete", None, 0, root.parent, &root.name);
    for who in affected {
        refresh(ctx, who);
    }
    Ok(())
}

/// Grant `role_id` to `who` in `scope_id`, optionally until `expires_at`. Returns the grant id
/// (an existing identical grant is reused, with the later expiry).
pub fn grant(
    ctx: &ReducerContext,
    who: Identity,
    role_id: u64,
    scope_id: u64,
    expires_at: Option<Timestamp>,
    by: Option<Identity>,
) -> Result<u64, String> {
    let role = ctx
        .db
        .authz_role()
        .id()
        .find(role_id)
        .ok_or("no such role")?;
    if scope_id != GLOBAL && ctx.db.authz_scope().id().find(scope_id).is_none() {
        return Err("no such scope".into());
    }
    if !role_usable_in(ctx, &role, scope_id) {
        return Err("that role isn't available in this scope".into());
    }
    if expires_at.is_some_and(|t| t <= ctx.timestamp) {
        return Err("expiry is in the past".into());
    }
    let existing = ctx
        .db
        .authz_grant()
        .by_identity_scope()
        .filter((who, scope_id))
        .find(|g| g.role_id == role_id);
    let id = match existing {
        Some(g) => {
            let expires_at = match (g.expires_at, expires_at) {
                (None, _) | (_, None) => None,
                (Some(a), Some(b)) => Some(a.max(b)),
            };
            let id = g.id;
            ctx.db
                .authz_grant()
                .id()
                .update(AuthzGrant { expires_at, ..g });
            id
        }
        None => {
            ctx.db
                .authz_grant()
                .insert(AuthzGrant {
                    id: 0,
                    identity: who,
                    role_id,
                    scope_id,
                    granted_by: by,
                    granted_at: ctx.timestamp,
                    expires_at,
                })
                .id
        }
    };
    if let Some(t) = expires_at {
        ctx.db.authz_job().insert(AuthzJob {
            scheduled_id: 0,
            scheduled_at: ScheduleAt::Time(t),
            kind: 0,
            target: id,
        });
    }
    audit(ctx, by, "grant", Some(who), role_id, scope_id, &role.name);
    refresh(ctx, who);
    Ok(id)
}

/// Remove a grant.
pub fn revoke(ctx: &ReducerContext, grant_id: u64, by: Option<Identity>) -> Result<(), String> {
    let g = ctx
        .db
        .authz_grant()
        .id()
        .find(grant_id)
        .ok_or("no such grant")?;
    ctx.db.authz_grant().id().delete(grant_id);
    audit(
        ctx,
        by,
        "revoke",
        Some(g.identity),
        g.role_id,
        g.scope_id,
        "",
    );
    refresh(ctx, g.identity);
    Ok(())
}

/// Recompute `authz_effective` and `authz_visible` for everyone (after changing watched
/// permissions, or editing the tables by hand).
pub fn refresh_all(ctx: &ReducerContext) {
    let people: HashSet<Identity> = ctx.db.authz_grant().iter().map(|g| g.identity).collect();
    let stale: HashSet<Identity> = ctx
        .db
        .authz_effective()
        .iter()
        .map(|v| v.identity)
        .collect();
    for who in people.union(&stale) {
        refresh(ctx, *who);
    }
}

// ---------------------------------------------------------------------------
// Client reducers (each checks the caller's permissions)
// ---------------------------------------------------------------------------

#[spacetimedb::reducer]
pub fn authz_create_scope(
    ctx: &ReducerContext,
    parent: u64,
    kind: String,
    name: String,
) -> Result<(), String> {
    require(ctx, PERM_SCOPE_CREATE, parent)?;
    create_scope(ctx, parent, &kind, &name, Some(ctx.sender())).map(|_| ())
}

#[spacetimedb::reducer]
pub fn authz_delete_scope(ctx: &ReducerContext, scope_id: u64) -> Result<(), String> {
    if scope_id == GLOBAL {
        return Err("can't delete the global scope".into());
    }
    if !settings(ctx).clients_delete_scopes {
        return Err("scopes are deleted through this module's own reducers".into());
    }
    require(ctx, PERM_SCOPE_DELETE, scope_id)?;
    delete_scope(ctx, scope_id, Some(ctx.sender()))
}

#[spacetimedb::reducer]
pub fn authz_grant_role(
    ctx: &ReducerContext,
    identity: Identity,
    role_id: u64,
    scope_id: u64,
    expires_at: Option<Timestamp>,
) -> Result<(), String> {
    check_delegate(ctx, PERM_GRANT, role_id, scope_id)?;
    grant(
        ctx,
        identity,
        role_id,
        scope_id,
        expires_at,
        Some(ctx.sender()),
    )
    .map(|_| ())
}

/// Revoke a grant: your own (leaving), or one you could have granted.
#[spacetimedb::reducer]
pub fn authz_revoke_grant(ctx: &ReducerContext, grant_id: u64) -> Result<(), String> {
    let g = ctx
        .db
        .authz_grant()
        .id()
        .find(grant_id)
        .ok_or("no such grant")?;
    if g.identity != ctx.sender() {
        check_delegate(ctx, PERM_GRANT, g.role_id, g.scope_id)?;
    }
    revoke(ctx, grant_id, Some(ctx.sender()))
}

/// Define a role in a scope, with permissions you hold there.
#[spacetimedb::reducer]
pub fn authz_create_role(
    ctx: &ReducerContext,
    scope_id: u64,
    name: String,
    permissions: Vec<String>,
    inherits: Vec<u64>,
) -> Result<(), String> {
    require(ctx, PERM_ROLE, scope_id)?;
    insert_role(
        ctx,
        scope_id,
        &name,
        permissions,
        inherits,
        false,
        Some(ctx.sender()),
    )
    .map(|_| ())
}

/// Change a non-system role. You must hold its old and new permissions in its scope.
#[spacetimedb::reducer]
pub fn authz_update_role(
    ctx: &ReducerContext,
    role_id: u64,
    permissions: Vec<String>,
    inherits: Vec<u64>,
) -> Result<(), String> {
    let role = ctx
        .db
        .authz_role()
        .id()
        .find(role_id)
        .ok_or("no such role")?;
    if role.system {
        return Err("system roles can only be changed by the module".into());
    }
    require(ctx, PERM_ROLE, role.scope_id)?;
    if !holds_all(ctx, ctx.sender(), &role.effective, role.scope_id) {
        return Err("you can only change roles whose permissions you hold".into());
    }
    check_perms(&permissions)?;
    check_inherits(ctx, role.scope_id, &inherits, Some(role_id))?;
    let effective = flatten(ctx, &permissions, &inherits);
    if !holds_all(ctx, ctx.sender(), &effective, role.scope_id) {
        return Err("you can only give a role permissions you hold".into());
    }
    let name = role.name.clone();
    ctx.db.authz_role().id().update(AuthzRole {
        permissions,
        inherits,
        ..role
    });
    recompute_roles(ctx);
    audit(
        ctx,
        Some(ctx.sender()),
        "role.update",
        None,
        role_id,
        role.scope_id,
        &name,
    );
    Ok(())
}

/// Delete a non-system role nobody holds or inherits.
#[spacetimedb::reducer]
pub fn authz_delete_role(ctx: &ReducerContext, role_id: u64) -> Result<(), String> {
    let role = ctx
        .db
        .authz_role()
        .id()
        .find(role_id)
        .ok_or("no such role")?;
    if role.system {
        return Err("system roles can only be deleted by the module".into());
    }
    require(ctx, PERM_ROLE, role.scope_id)?;
    if !holds_all(ctx, ctx.sender(), &role.effective, role.scope_id) {
        return Err("you can only delete roles whose permissions you hold".into());
    }
    if ctx
        .db
        .authz_grant()
        .role_id()
        .filter(role_id)
        .next()
        .is_some()
    {
        return Err("role is still granted".into());
    }
    if ctx
        .db
        .authz_role()
        .iter()
        .any(|r| r.inherits.contains(&role_id))
    {
        return Err("another role inherits it".into());
    }
    for inv in ctx
        .db
        .authz_invite()
        .iter()
        .filter(|i| i.role_id == role_id)
        .collect::<Vec<_>>()
    {
        delete_invite(ctx, inv.id);
    }
    ctx.db.authz_role().id().delete(role_id);
    audit(
        ctx,
        Some(ctx.sender()),
        "role.delete",
        None,
        role_id,
        role.scope_id,
        &role.name,
    );
    Ok(())
}

/// Create an invite. Generate `code` on the client (at least 16 random characters) and share it.
/// The code is stored in a private table; clients only ever see the invite's metadata.
#[spacetimedb::reducer]
pub fn authz_create_invite(
    ctx: &ReducerContext,
    code: String,
    role_id: u64,
    scope_id: u64,
    max_uses: u32,
    expires_at: Option<Timestamp>,
    grant_ttl_secs: u64,
) -> Result<(), String> {
    check_delegate(ctx, PERM_INVITE, role_id, scope_id)?;
    if code.len() < MIN_INVITE_CODE || code.len() > 128 {
        return Err(format!(
            "invite codes must be {MIN_INVITE_CODE}-128 characters"
        ));
    }
    if ctx.db.authz_invite_code().code().find(&code).is_some() {
        return Err("that code is taken".into());
    }
    if expires_at.is_some_and(|t| t <= ctx.timestamp) {
        return Err("expiry is in the past".into());
    }
    let inv = ctx.db.authz_invite().insert(AuthzInvite {
        id: 0,
        role_id,
        scope_id,
        created_by: ctx.sender(),
        created_at: ctx.timestamp,
        expires_at,
        max_uses,
        uses: 0,
        grant_ttl_secs,
    });
    ctx.db.authz_invite_code().insert(AuthzInviteCode {
        code,
        invite_id: inv.id,
    });
    if let Some(t) = expires_at {
        ctx.db.authz_job().insert(AuthzJob {
            scheduled_id: 0,
            scheduled_at: ScheduleAt::Time(t),
            kind: 1,
            target: inv.id,
        });
    }
    audit(
        ctx,
        Some(ctx.sender()),
        "invite.create",
        None,
        role_id,
        scope_id,
        "",
    );
    Ok(())
}

#[spacetimedb::reducer]
pub fn authz_revoke_invite(ctx: &ReducerContext, invite_id: u64) -> Result<(), String> {
    let inv = ctx
        .db
        .authz_invite()
        .id()
        .find(invite_id)
        .ok_or("no such invite")?;
    if inv.created_by != ctx.sender() {
        check_delegate(ctx, PERM_INVITE, inv.role_id, inv.scope_id)?;
    }
    delete_invite(ctx, invite_id);
    audit(
        ctx,
        Some(ctx.sender()),
        "invite.revoke",
        None,
        inv.role_id,
        inv.scope_id,
        "",
    );
    Ok(())
}

/// Redeem an invite code. The inviter must still be allowed to hand out the role.
#[spacetimedb::reducer]
pub fn authz_redeem_invite(ctx: &ReducerContext, code: String) -> Result<(), String> {
    let link = ctx
        .db
        .authz_invite_code()
        .code()
        .find(&code)
        .ok_or("invalid invite")?;
    let inv = ctx
        .db
        .authz_invite()
        .id()
        .find(link.invite_id)
        .ok_or("invalid invite")?;
    if inv.expires_at.is_some_and(|t| t <= ctx.timestamp) {
        // (Deleting it here would be rolled back with the error; the scheduled job removes it.)
        return Err("invite expired".into());
    }
    let role = ctx
        .db
        .authz_role()
        .id()
        .find(inv.role_id)
        .ok_or("invalid invite")?;
    if !can(ctx, inv.created_by, PERM_INVITE, inv.scope_id)
        || !holds_all(ctx, inv.created_by, &role.effective, inv.scope_id)
    {
        return Err("the inviter can no longer grant this role".into());
    }
    let expires_at = (inv.grant_ttl_secs > 0)
        .then(|| ctx.timestamp + std::time::Duration::from_secs(inv.grant_ttl_secs));
    grant(
        ctx,
        ctx.sender(),
        inv.role_id,
        inv.scope_id,
        expires_at,
        Some(inv.created_by),
    )?;
    let uses = inv.uses + 1;
    audit(
        ctx,
        Some(ctx.sender()),
        "invite.redeem",
        Some(ctx.sender()),
        inv.role_id,
        inv.scope_id,
        "",
    );
    if inv.max_uses > 0 && uses >= inv.max_uses {
        delete_invite(ctx, inv.id);
    } else {
        ctx.db
            .authz_invite()
            .id()
            .update(AuthzInvite { uses, ..inv });
    }
    Ok(())
}

/// Scheduled: expire a grant or invite on time. Not callable by clients.
#[spacetimedb::reducer]
pub fn authz_run_job(ctx: &ReducerContext, job: AuthzJob) -> Result<(), String> {
    if ctx.sender() != ctx.database_identity() {
        return Err("scheduler only".into());
    }
    match job.kind {
        0 => {
            if let Some(g) = ctx.db.authz_grant().id().find(job.target)
                && !live(&g, ctx.timestamp)
            {
                ctx.db.authz_grant().id().delete(g.id);
                audit(
                    ctx,
                    None,
                    "expire",
                    Some(g.identity),
                    g.role_id,
                    g.scope_id,
                    "",
                );
                refresh(ctx, g.identity);
            }
        }
        _ => {
            if let Some(inv) = ctx.db.authz_invite().id().find(job.target)
                && inv.expires_at.is_some_and(|t| t <= ctx.timestamp)
            {
                delete_invite(ctx, inv.id);
                audit(
                    ctx,
                    None,
                    "invite.expire",
                    None,
                    inv.role_id,
                    inv.scope_id,
                    "",
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn check_name(s: &str) -> Result<(), String> {
    if s.trim().is_empty() || s.chars().count() > MAX_NAME {
        return Err(format!("names must be 1-{MAX_NAME} characters"));
    }
    Ok(())
}

fn check_perms(perms: &[String]) -> Result<(), String> {
    if perms.len() > MAX_PERMS {
        return Err(format!("at most {MAX_PERMS} permissions per role"));
    }
    for p in perms {
        let ok = !p.is_empty()
            && p.len() <= 128
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '*'))
            && (p == "*"
                || !p.contains('*')
                || (p.ends_with(".*") && !p[..p.len() - 2].contains('*')));
        if !ok {
            return Err(format!("bad permission `{p}`: use a.b.c, a.*, or *"));
        }
    }
    Ok(())
}

/// Inherited roles must exist, be usable in `scope_id`, and not form a cycle.
fn check_inherits(
    ctx: &ReducerContext,
    scope_id: u64,
    inherits: &[u64],
    this: Option<u64>,
) -> Result<(), String> {
    for &id in inherits {
        let r = ctx
            .db
            .authz_role()
            .id()
            .find(id)
            .ok_or("inherited role doesn't exist")?;
        if !(r.scope_id == GLOBAL
            || lineage(ctx, scope_id).is_some_and(|l| l.contains(&r.scope_id)))
        {
            return Err("inherited role isn't available in this scope".into());
        }
    }
    if let Some(me) = this {
        let mut stack = inherits.to_vec();
        let mut seen = HashSet::new();
        while let Some(id) = stack.pop() {
            if id == me {
                return Err("roles can't inherit themselves".into());
            }
            if seen.insert(id)
                && let Some(r) = ctx.db.authz_role().id().find(id)
            {
                stack.extend(r.inherits);
            }
        }
    }
    Ok(())
}

fn flatten(ctx: &ReducerContext, perms: &[String], inherits: &[u64]) -> Vec<String> {
    let mut out: BTreeSet<String> = perms.iter().cloned().collect();
    let mut stack = inherits.to_vec();
    let mut seen = HashSet::new();
    while let Some(id) = stack.pop() {
        if seen.insert(id)
            && let Some(r) = ctx.db.authz_role().id().find(id)
        {
            out.extend(r.permissions);
            stack.extend(r.inherits);
        }
    }
    out.into_iter().collect()
}

fn insert_role(
    ctx: &ReducerContext,
    scope_id: u64,
    name: &str,
    permissions: Vec<String>,
    inherits: Vec<u64>,
    system: bool,
    by: Option<Identity>,
) -> Result<u64, String> {
    check_name(name)?;
    check_perms(&permissions)?;
    if scope_id != GLOBAL && ctx.db.authz_scope().id().find(scope_id).is_none() {
        return Err("no such scope".into());
    }
    if ctx
        .db
        .authz_role()
        .by_scope_name()
        .filter((scope_id, name))
        .next()
        .is_some()
    {
        return Err("a role with that name exists in this scope".into());
    }
    check_inherits(ctx, scope_id, &inherits, None)?;
    let effective = flatten(ctx, &permissions, &inherits);
    if let Some(who) = by
        && !holds_all(ctx, who, &effective, scope_id)
    {
        return Err("you can only give a role permissions you hold".into());
    }
    let r = ctx.db.authz_role().insert(AuthzRole {
        id: 0,
        scope_id,
        name: name.to_string(),
        permissions,
        inherits,
        effective,
        system,
    });
    audit(ctx, by, "role.create", None, r.id, scope_id, name);
    Ok(r.id)
}

/// Re-flatten every role (roles are few), then refresh everyone whose permissions changed.
fn recompute_roles(ctx: &ReducerContext) {
    let mut changed = Vec::new();
    for r in ctx.db.authz_role().iter().collect::<Vec<_>>() {
        let effective = flatten(ctx, &r.permissions, &r.inherits);
        if effective != r.effective {
            changed.push(r.id);
            ctx.db
                .authz_role()
                .id()
                .update(AuthzRole { effective, ..r });
        }
    }
    let mut people = HashSet::new();
    for id in changed {
        people.extend(
            ctx.db
                .authz_grant()
                .role_id()
                .filter(id)
                .map(|g| g.identity),
        );
    }
    for who in people {
        refresh(ctx, who);
    }
}

fn delete_invite(ctx: &ReducerContext, invite_id: u64) {
    ctx.db.authz_invite().id().delete(invite_id);
    ctx.db.authz_invite_code().invite_id().delete(invite_id);
}

/// Everyone with a live grant on `scope_id`'s ancestors, including global ones (not the scope itself).
fn holders_above(ctx: &ReducerContext, scope_id: u64) -> HashSet<Identity> {
    let mut out = HashSet::new();
    for s in lineage(ctx, scope_id)
        .unwrap_or_default()
        .into_iter()
        .skip(1)
    {
        out.extend(
            ctx.db
                .authz_grant()
                .scope_id()
                .filter(s)
                .filter(|g| live(g, ctx.timestamp))
                .map(|g| g.identity),
        );
    }
    out
}

fn watched(ctx: &ReducerContext) -> Vec<String> {
    let mut w = vec![
        MEMBER.to_string(),
        PERM_GRANT.into(),
        PERM_INVITE.into(),
        PERM_AUDIT.into(),
    ];
    if let Some(c) = ctx.db.authz_config().key().find(0) {
        for p in c.settings.watch {
            if !w.contains(&p) {
                w.push(p);
            }
        }
    }
    w
}

/// Rebuild `who`'s rows in `authz_effective` and `authz_visible`: their flattened permissions in
/// every scope they reach, and for each watched permission every scope where they hold it. Grants
/// expand down the tree; a global grant expands to every scope, so keep global grants for a few
/// people (the module owner bypasses RLS anyway).
fn refresh(ctx: &ReducerContext, who: Identity) {
    let watch = watched(ctx);
    let mut eff: HashMap<u64, (BTreeSet<String>, Option<Timestamp>)> = HashMap::new();
    let mut children: HashMap<u64, Vec<u64>> = HashMap::new();
    for g in ctx.db.authz_grant().identity().filter(who) {
        if !live(&g, ctx.timestamp) {
            continue;
        }
        let Some(role) = ctx.db.authz_role().id().find(g.role_id) else {
            continue;
        };
        // The grant's scope and its whole subtree.
        let mut scopes = vec![g.scope_id];
        let mut i = 0;
        while i < scopes.len() {
            let kids = children
                .entry(scopes[i])
                .or_insert_with(|| {
                    ctx.db
                        .authz_scope()
                        .parent()
                        .filter(scopes[i])
                        .map(|c| c.id)
                        .collect()
                })
                .clone();
            scopes.extend(kids);
            i += 1;
        }
        for s in scopes {
            let e = eff.entry(s).or_default();
            e.0.extend(role.effective.iter().cloned());
            e.1 = earliest(e.1, g.expires_at);
        }
    }

    // authz_effective: one row per reached scope.
    let mut old: HashMap<u64, AuthzEffective> = ctx
        .db
        .authz_effective()
        .identity()
        .filter(who)
        .map(|e| (e.scope_id, e))
        .collect();
    for (&scope_id, (perms, valid_until)) in &eff {
        let perms: Vec<String> = perms.iter().cloned().collect();
        match old.remove(&scope_id) {
            Some(row) if row.perms == perms && row.valid_until == *valid_until => {}
            Some(row) => {
                ctx.db.authz_effective().id().update(AuthzEffective {
                    perms,
                    valid_until: *valid_until,
                    ..row
                });
            }
            None => {
                ctx.db.authz_effective().insert(AuthzEffective {
                    id: 0,
                    identity: who,
                    scope_id,
                    perms,
                    valid_until: *valid_until,
                });
            }
        }
    }
    for row in old.into_values() {
        ctx.db.authz_effective().id().delete(row.id);
    }

    // authz_visible: (scope, watched permission) pairs.
    let mut want: HashSet<(u64, String)> = HashSet::new();
    for (&scope_id, (perms, _)) in &eff {
        for w in &watch {
            if w.is_empty() || perms.iter().any(|h| covers(h, w)) {
                want.insert((scope_id, w.clone()));
            }
        }
    }
    for row in ctx
        .db
        .authz_visible()
        .identity()
        .filter(who)
        .collect::<Vec<_>>()
    {
        if !want.remove(&(row.scope_id, row.perm.clone())) {
            ctx.db.authz_visible().id().delete(row.id);
        }
    }
    for (scope_id, perm) in want {
        ctx.db.authz_visible().insert(AuthzVisible {
            id: 0,
            identity: who,
            scope_id,
            perm,
        });
    }
}

fn audit(
    ctx: &ReducerContext,
    actor: Option<Identity>,
    action: &str,
    target: Option<Identity>,
    role_id: u64,
    scope_id: u64,
    detail: &str,
) {
    ctx.db.authz_audit().insert(AuthzAudit {
        id: 0,
        at: ctx.timestamp,
        actor,
        action: action.to_string(),
        target: target.unwrap_or(Identity::ZERO),
        role_id,
        scope_id,
        detail: detail.to_string(),
    });
}
