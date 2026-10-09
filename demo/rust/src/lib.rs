//! Demo: a team workspace. Anyone can create a workspace (and is its admin); admins add
//! projects, invite people, define roles and hand them out; docs are visible only to people
//! with `doc.read` there. Serves the web client at `/route/`.

#[path = "../../../rust/authz.rs"]
pub mod authz;

use http::{StatusCode, header};
use spacetimedb::http::{Body, HandlerContext, Request, Response, Router, handler, router};
use spacetimedb::{Identity, ReducerContext, Table, Timestamp};

const PAGE: &str = include_str!("../../web/dist/index.html");

#[spacetimedb::table(accessor = demo_profile, public)]
pub struct DemoProfile {
    #[primary_key]
    pub identity: Identity,
    pub name: String,
}

#[spacetimedb::table(accessor = demo_doc, public)]
pub struct DemoDoc {
    #[primary_key]
    #[auto_inc]
    pub id: u64,
    #[index(btree)]
    pub scope_id: u64,
    pub title: String,
    pub body: String,
    pub author: Identity,
    pub updated_at: Timestamp,
}

// Docs are visible to people holding `doc.read` in the doc's scope (or above it).
authz_rls!(DEMO_DOC_READ, "demo_doc", "scope_id", "doc.read");

#[spacetimedb::reducer(init)]
pub fn init(ctx: &ReducerContext) -> Result<(), String> {
    authz::configure(
        ctx,
        authz::AuthzSettings {
            watch: vec!["doc.read".into()],
            clients_delete_scopes: false,
        },
    );
    authz::bootstrap(ctx, ctx.sender())?;
    let viewer = authz::create_role(ctx, authz::GLOBAL, "viewer", &["doc.read"], &[])?;
    let editor = authz::create_role(ctx, authz::GLOBAL, "editor", &["doc.write"], &[viewer])?;
    authz::create_role(
        ctx,
        authz::GLOBAL,
        "admin",
        &[
            "doc.delete",
            "authz.grant",
            "authz.invite",
            "authz.role",
            "authz.scope.create",
            "authz.scope.delete",
            "authz.audit",
        ],
        &[editor],
    )?;
    Ok(())
}

#[spacetimedb::reducer(client_connected)]
pub fn connected(ctx: &ReducerContext) {
    if ctx
        .db
        .demo_profile()
        .identity()
        .find(ctx.sender())
        .is_none()
    {
        let hex = ctx.sender().to_hex().to_string();
        ctx.db.demo_profile().insert(DemoProfile {
            identity: ctx.sender(),
            name: format!("guest-{}", &hex[hex.len() - 4..]),
        });
    }
}

#[spacetimedb::reducer]
pub fn demo_set_name(ctx: &ReducerContext, name: String) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() || name.chars().count() > 24 {
        return Err("name must be 1-24 characters".into());
    }
    ctx.db.demo_profile().identity().update(DemoProfile {
        identity: ctx.sender(),
        name,
    });
    Ok(())
}

/// Anyone can start a workspace; the module makes them its admin.
#[spacetimedb::reducer]
pub fn demo_create_workspace(ctx: &ReducerContext, name: String) -> Result<(), String> {
    let ws = authz::create_scope(
        ctx,
        authz::GLOBAL,
        "workspace",
        name.trim(),
        Some(ctx.sender()),
    )?;
    let admin = admin_role(ctx)?;
    authz::grant(ctx, ctx.sender(), admin, ws, None, None)?;
    Ok(())
}

/// Delete a workspace or project: its docs first, then the scopes, grants and invites.
#[spacetimedb::reducer]
pub fn demo_delete_scope(ctx: &ReducerContext, scope_id: u64) -> Result<(), String> {
    authz::require(ctx, authz::PERM_SCOPE_DELETE, scope_id)?;
    for s in authz::subtree(ctx, scope_id) {
        for d in ctx.db.demo_doc().scope_id().filter(s).collect::<Vec<_>>() {
            ctx.db.demo_doc().id().delete(d.id);
        }
    }
    authz::delete_scope(ctx, scope_id, Some(ctx.sender()))
}

#[spacetimedb::reducer]
pub fn demo_create_doc(
    ctx: &ReducerContext,
    scope_id: u64,
    title: String,
    body: String,
) -> Result<(), String> {
    authz::require(ctx, "doc.write", scope_id)?;
    let title = title.trim().to_string();
    if title.is_empty() || title.chars().count() > 80 || body.len() > 4000 {
        return Err("title 1-80 characters, body up to 4000".into());
    }
    ctx.db.demo_doc().insert(DemoDoc {
        id: 0,
        scope_id,
        title,
        body,
        author: ctx.sender(),
        updated_at: ctx.timestamp,
    });
    Ok(())
}

#[spacetimedb::reducer]
pub fn demo_update_doc(ctx: &ReducerContext, id: u64, body: String) -> Result<(), String> {
    let doc = ctx.db.demo_doc().id().find(id).ok_or("no such doc")?;
    authz::require(ctx, "doc.write", doc.scope_id)?;
    if body.len() > 4000 {
        return Err("body up to 4000".into());
    }
    ctx.db.demo_doc().id().update(DemoDoc {
        body,
        updated_at: ctx.timestamp,
        ..doc
    });
    Ok(())
}

#[spacetimedb::reducer]
pub fn demo_delete_doc(ctx: &ReducerContext, id: u64) -> Result<(), String> {
    let doc = ctx.db.demo_doc().id().find(id).ok_or("no such doc")?;
    authz::require(ctx, "doc.delete", doc.scope_id)?;
    ctx.db.demo_doc().id().delete(id);
    Ok(())
}

/// Benchmark: `n` permission checks for the caller in `scope_id`.
#[spacetimedb::reducer]
pub fn demo_bench(ctx: &ReducerContext, scope_id: u64, n: u32) {
    let mut yes = 0u32;
    for i in 0..n {
        let perm = if i % 2 == 0 { "doc.write" } else { "doc.nope" };
        yes += authz::can(ctx, ctx.sender(), perm, scope_id) as u32;
    }
    log::info!("demo_bench: {yes}/{n} allowed");
}

fn admin_role(ctx: &ReducerContext) -> Result<u64, String> {
    authz::find_role(ctx, authz::GLOBAL, "admin").ok_or_else(|| "admin role missing".into())
}

#[handler]
fn page(_ctx: &mut HandlerContext, _req: Request) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_bytes(PAGE))
        .unwrap()
}

#[router]
fn routes() -> Router {
    Router::new().get("/", page)
}
