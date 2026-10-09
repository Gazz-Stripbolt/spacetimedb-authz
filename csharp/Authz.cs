// Authz.cs: roles, scopes and grants for SpacetimeDB C# modules, one drop-in file.
//
// The C# twin of rust/authz.rs and the spacetimedb-authz TypeScript submodule. Same tables,
// reducers and rules, so the same clients work against all three.
//
// Drop this file into your module project and set it up from Init:
//
//     [Reducer(ReducerKind.Init)]
//     public static void Init(ReducerContext ctx)
//     {
//         AuthzConfigure(ctx, new AuthzSettings { Watch = ["doc.read"] });
//         AuthzBootstrap(ctx, ctx.Sender);                       // the publisher gets `owner` (`*`)
//         var viewer = AuthzNewRole(ctx, 0, "viewer", ["doc.read"], []);
//         AuthzNewRole(ctx, 0, "editor", ["doc.write"], [viewer]);
//     }
//
//     // in your reducers
//     AuthzRequire(ctx, "doc.write", doc.ScopeId);
//
// Roles hold permission strings (`doc.write`, `doc.*`, `*`) and inherit other roles. Scopes form a
// tree; a grant on a scope applies below it; scope 0 is global. Grants can expire exactly on
// time. Invites grant a role on redemption. Clients can only hand out what they hold. Every
// change is audited. Row-level security shows clients only the scopes they're in.

#pragma warning disable STDB_UNSTABLE
#nullable enable

using SpacetimeDB;

/// <summary>Tunables.</summary>
[SpacetimeDB.Type]
public partial struct AuthzSettings
{
    /// <summary>Permissions to materialise in authz_visible for your own RLS rules (e.g. "doc.read").</summary>
    public List<string> Watch;
    /// <summary>Allow the authz_delete_scope reducer (off: delete through your own reducer that cleans up first).</summary>
    public bool ClientsDeleteScopes;

    public AuthzSettings()
    {
        Watch = [];
        ClientsDeleteScopes = false;
    }
}

public static partial class Module
{
    public const string AUTHZ_GRANT = "authz.grant";
    public const string AUTHZ_INVITE = "authz.invite";
    public const string AUTHZ_ROLE = "authz.role";
    public const string AUTHZ_SCOPE_CREATE = "authz.scope.create";
    public const string AUTHZ_SCOPE_DELETE = "authz.scope.delete";
    public const string AUTHZ_AUDIT = "authz.audit";
    /// <summary>The perm value in authz_visible meaning "has any grant reaching this scope".</summary>
    public const string AUTHZ_MEMBER = "";
    public const ulong AUTHZ_GLOBAL = 0;

    const int AuthzMaxName = 64;
    const int AuthzMaxPerms = 64;
    const int AuthzMinInviteCode = 16;

    // -----------------------------------------------------------------------
    // Tables
    // -----------------------------------------------------------------------

    [SpacetimeDB.Table(Accessor = "AuthzConfig")]
    public partial struct AuthzConfig
    {
        [SpacetimeDB.PrimaryKey]
        public byte Key;
        public AuthzSettings Settings;
    }

    /// <summary>Roles. ScopeId 0 = usable everywhere; otherwise only in that scope and below.</summary>
    [SpacetimeDB.Table(Accessor = "AuthzRole", Public = true)]
    [SpacetimeDB.Index.BTree(Accessor = "ByScopeName", Columns = new[] { nameof(ScopeId), nameof(Name) })]
    public partial struct AuthzRole
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        [SpacetimeDB.Index.BTree]
        public ulong ScopeId;
        public string Name;
        public List<string> Permissions;
        public List<ulong> Inherits;
        /// <summary>Permissions plus everything inherited, flattened. Maintained by the module.</summary>
        public List<string> Effective;
        /// <summary>Defined by module code (clients can't change or delete it).</summary>
        public bool System;
    }

    /// <summary>The scope tree. Path lists the ancestors, root first (not 0, not the scope itself).</summary>
    [SpacetimeDB.Table(Accessor = "AuthzScope", Public = true)]
    public partial struct AuthzScope
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        [SpacetimeDB.Index.BTree]
        public ulong Parent;
        public string Kind;
        public string Name;
        public List<ulong> Path;
        public Identity? CreatedBy;
        public Timestamp CreatedAt;
    }

    [SpacetimeDB.Table(Accessor = "AuthzGrant", Public = true)]
    [SpacetimeDB.Index.BTree(Accessor = "ByIdentityScope", Columns = new[] { nameof(Identity), nameof(ScopeId) })]
    public partial struct AuthzGrant
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        [SpacetimeDB.Index.BTree]
        public Identity Identity;
        [SpacetimeDB.Index.BTree]
        public ulong RoleId;
        [SpacetimeDB.Index.BTree]
        public ulong ScopeId;
        /// <summary>null when module code granted it.</summary>
        public Identity? GrantedBy;
        public Timestamp GrantedAt;
        public Timestamp? ExpiresAt;
    }

    /// <summary>Invite metadata (the code itself is private, in authz_invite_code).</summary>
    [SpacetimeDB.Table(Accessor = "AuthzInvite", Public = true)]
    public partial struct AuthzInvite
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        public ulong RoleId;
        [SpacetimeDB.Index.BTree]
        public ulong ScopeId;
        public Identity CreatedBy;
        public Timestamp CreatedAt;
        public Timestamp? ExpiresAt;
        /// <summary>0 = unlimited.</summary>
        public uint MaxUses;
        public uint Uses;
        /// <summary>Grants made from this invite expire after this many seconds (0 = never).</summary>
        public ulong GrantTtlSecs;
    }

    [SpacetimeDB.Table(Accessor = "AuthzInviteCode")]
    public partial struct AuthzInviteCode
    {
        [SpacetimeDB.PrimaryKey]
        public string Code;
        [SpacetimeDB.Unique]
        public ulong InviteId;
    }

    /// <summary>
    /// Who holds which watched permission where, expanded down the scope tree: the join target
    /// for row-level security. Public with no RLS of its own (SpacetimeDB 2.11 rejects RLS joins
    /// through a table that has RLS), so it reveals who can see what.
    /// </summary>
    [SpacetimeDB.Table(Accessor = "AuthzVisible", Public = true)]
    public partial struct AuthzVisible
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        [SpacetimeDB.Index.BTree]
        public Identity Identity;
        [SpacetimeDB.Index.BTree]
        public ulong ScopeId;
        public string Perm;
    }

    /// <summary>
    /// Each identity's flattened permissions in every scope they reach (grants inherited down the
    /// tree, roles flattened), so a check is one index lookup. Rebuilt with authz_visible. Private.
    /// </summary>
    [SpacetimeDB.Table(Accessor = "AuthzEffective")]
    [SpacetimeDB.Index.BTree(Accessor = "ByIdentityScope", Columns = new[] { nameof(Identity), nameof(ScopeId) })]
    public partial struct AuthzEffective
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        [SpacetimeDB.Index.BTree]
        public Identity Identity;
        [SpacetimeDB.Index.BTree]
        public ulong ScopeId;
        public List<string> Perms;
        /// <summary>The earliest expiry among the grants behind it; past it, checks take the slow path.</summary>
        public Timestamp? ValidUntil;
    }

    [SpacetimeDB.Table(Accessor = "AuthzAudit", Public = true)]
    public partial struct AuthzAudit
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        public Timestamp At;
        /// <summary>null = module code or the scheduler.</summary>
        public Identity? Actor;
        public string Action;
        /// <summary>Who the change was about; the zero identity when nobody in particular.</summary>
        public Identity Target;
        public ulong RoleId;
        [SpacetimeDB.Index.BTree]
        public ulong ScopeId;
        public string Detail;
    }

    /// <summary>One-shot jobs: expire a grant (Kind 0) or an invite (Kind 1) on time.</summary>
    [SpacetimeDB.Table(Accessor = "AuthzJob", Scheduled = nameof(AuthzRunJob), ScheduledAt = nameof(AuthzJob.ScheduledAt))]
    public partial struct AuthzJob
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong ScheduledId;
        public ScheduleAt ScheduledAt;
        public byte Kind;
        public ulong Target;
    }

    // -----------------------------------------------------------------------
    // Row-level security (one rule per table: SpacetimeDB 2.11 drops live updates from a join
    // rule when the table has a second rule)
    // -----------------------------------------------------------------------

    /// <summary>Grants in scopes you're a member of (the roster).</summary>
    [SpacetimeDB.ClientVisibilityFilter]
    public static readonly Filter AUTHZ_GRANT_MEMBER = new Filter.Sql(
        "SELECT authz_grant.* FROM authz_grant JOIN authz_visible ON authz_grant.scope_id = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = ''"
    );

    /// <summary>Scopes you have any grant in (directly or through a parent).</summary>
    [SpacetimeDB.ClientVisibilityFilter]
    public static readonly Filter AUTHZ_SCOPE_MEMBER = new Filter.Sql(
        "SELECT authz_scope.* FROM authz_scope JOIN authz_visible ON authz_scope.id = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = ''"
    );

    /// <summary>Invites in scopes where you can invite.</summary>
    [SpacetimeDB.ClientVisibilityFilter]
    public static readonly Filter AUTHZ_INVITE_MANAGED = new Filter.Sql(
        "SELECT authz_invite.* FROM authz_invite JOIN authz_visible ON authz_invite.scope_id = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = 'authz.invite'"
    );

    /// <summary>Audit entries in scopes where you hold authz.audit.</summary>
    [SpacetimeDB.ClientVisibilityFilter]
    public static readonly Filter AUTHZ_AUDIT_MANAGED = new Filter.Sql(
        "SELECT authz_audit.* FROM authz_audit JOIN authz_visible ON authz_audit.scope_id = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = 'authz.audit'"
    );

    /// <summary>
    /// An RLS rule that shows rows of `table` to clients holding `perm` in the row's scope
    /// (`column`, snake_case), including through parent scopes and global grants:
    /// <code>[ClientVisibilityFilter] public static readonly Filter DOC_READ = AuthzRls("doc", "scope_id", "doc.read");</code>
    /// Add `perm` to AuthzSettings.Watch and index the column.
    /// </summary>
    public static Filter AuthzRls(string table, string column, string perm) => new Filter.Sql(
        $"SELECT {table}.* FROM {table} JOIN authz_visible ON {table}.{column} = authz_visible.scope_id WHERE authz_visible.identity = :sender AND authz_visible.perm = '{perm}'"
    );

    // -----------------------------------------------------------------------
    // Checks
    // -----------------------------------------------------------------------

    /// <summary>Does a held permission cover a requested one? `*` covers everything; `doc.*` covers `doc.x`, `doc.x.y`, `doc.*`.</summary>
    public static bool AuthzCovers(string held, string wanted)
    {
        if (held == "*" || held == wanted) return true;
        if (!held.EndsWith(".*")) return false;
        var prefix = held[..^2];
        return wanted.Length > prefix.Length + 1 && wanted.StartsWith(prefix, StringComparison.Ordinal) && wanted[prefix.Length] == '.';
    }

    static bool AuthzLive(AuthzGrant g, Timestamp now) =>
        g.ExpiresAt is not { } t || t.MicrosecondsSinceUnixEpoch > now.MicrosecondsSinceUnixEpoch;

    /// <summary>The scope and all its ancestors, nearest first, ending with GLOBAL; null if unknown.</summary>
    static List<ulong>? AuthzLineage(ReducerContext ctx, ulong scopeId)
    {
        if (scopeId == AUTHZ_GLOBAL) return [AUTHZ_GLOBAL];
        if (ctx.Db.AuthzScope.Id.Find(scopeId) is not { } s) return null;
        var out_ = new List<ulong> { scopeId };
        for (var i = s.Path.Count - 1; i >= 0; i--) out_.Add(s.Path[i]);
        out_.Add(AUTHZ_GLOBAL);
        return out_;
    }

    /// <summary>Can `who` do `perm` in `scopeId`? One lookup in the precomputed authz_effective.</summary>
    public static bool AuthzCan(ReducerContext ctx, Identity who, string perm, ulong scopeId)
    {
        foreach (var p in AuthzPermissions(ctx, who, scopeId)) if (AuthzCovers(p, perm)) return true;
        return false;
    }

    /// <summary>AuthzCan for the caller; throws "permission denied: perm".</summary>
    public static void AuthzRequire(ReducerContext ctx, string perm, ulong scopeId)
    {
        if (!AuthzCan(ctx, ctx.Sender, perm, scopeId)) throw new Exception($"permission denied: {perm}");
    }

    /// <summary>Every permission `who` holds in `scopeId` (directly or inherited), deduplicated.</summary>
    public static List<string> AuthzPermissions(ReducerContext ctx, Identity who, ulong scopeId)
    {
        foreach (var e in ctx.Db.AuthzEffective.ByIdentityScope.Filter((who, scopeId)))
        {
            if (e.ValidUntil is not { } t || t.MicrosecondsSinceUnixEpoch > ctx.Timestamp.MicrosecondsSinceUnixEpoch) return e.Perms;
            // A grant behind the cached row just expired and the expiry job hasn't run yet.
            return AuthzCompute(ctx, who, scopeId).Perms;
        }
        return []; // no row: no live grant reaches this scope
    }

    /// <summary>The slow path: walk the scope's lineage and the live grants on it.</summary>
    static (List<string> Perms, Timestamp? Until) AuthzCompute(ReducerContext ctx, Identity who, ulong scopeId)
    {
        var out_ = new SortedSet<string>(StringComparer.Ordinal);
        Timestamp? until = null;
        foreach (var s in AuthzLineage(ctx, scopeId) ?? [])
        {
            foreach (var g in ctx.Db.AuthzGrant.ByIdentityScope.Filter((who, s)))
            {
                if (AuthzLive(g, ctx.Timestamp) && ctx.Db.AuthzRole.Id.Find(g.RoleId) is { } role)
                {
                    out_.UnionWith(role.Effective);
                    until = AuthzEarliest(until, g.ExpiresAt);
                }
            }
        }
        return ([.. out_], until);
    }

    static Timestamp? AuthzEarliest(Timestamp? a, Timestamp? b) =>
        a is { } x && b is { } y ? (x.MicrosecondsSinceUnixEpoch <= y.MicrosecondsSinceUnixEpoch ? x : y) : a ?? b;

    static bool AuthzHoldsAll(ReducerContext ctx, Identity who, List<string> perms, ulong scopeId)
    {
        var mine = AuthzPermissions(ctx, who, scopeId);
        return perms.All(p => mine.Any(h => AuthzCovers(h, p)));
    }

    static AuthzRole AuthzCheckDelegate(ReducerContext ctx, string meta, ulong roleId, ulong scopeId)
    {
        AuthzRequire(ctx, meta, scopeId);
        var role = ctx.Db.AuthzRole.Id.Find(roleId) ?? throw new Exception("no such role");
        if (!AuthzRoleUsableIn(ctx, role, scopeId)) throw new Exception("that role isn't available in this scope");
        if (!AuthzHoldsAll(ctx, ctx.Sender, role.Effective, scopeId))
        {
            throw new Exception("you can only hand out roles whose permissions you hold");
        }
        return role;
    }

    static bool AuthzRoleUsableIn(ReducerContext ctx, AuthzRole role, ulong scopeId) =>
        role.ScopeId == AUTHZ_GLOBAL || (AuthzLineage(ctx, scopeId)?.Contains(role.ScopeId) ?? false);

    // -----------------------------------------------------------------------
    // Library API: call these from your own reducers (no permission checks)
    // -----------------------------------------------------------------------

    /// <summary>Store settings (from Init). Call AuthzRefreshAll after changing Watch on a live database.</summary>
    public static void AuthzConfigure(ReducerContext ctx, AuthzSettings settings)
    {
        var row = new AuthzConfig { Key = 0, Settings = settings };
        if (ctx.Db.AuthzConfig.Key.Find(0) is not null) ctx.Db.AuthzConfig.Key.Update(row);
        else ctx.Db.AuthzConfig.Insert(row);
    }

    public static AuthzSettings AuthzGetSettings(ReducerContext ctx) => ctx.Db.AuthzConfig.Key.Find(0)?.Settings ?? new AuthzSettings();

    /// <summary>scopeId and every scope below it.</summary>
    public static List<ulong> AuthzSubtree(ReducerContext ctx, ulong scopeId)
    {
        var out_ = new List<ulong> { scopeId };
        for (var i = 0; i < out_.Count; i++)
        {
            foreach (var c in ctx.Db.AuthzScope.Parent.Filter(out_[i])) out_.Add(c.Id);
        }
        return out_;
    }

    /// <summary>A role's id by scope and name.</summary>
    public static ulong? AuthzFindRole(ReducerContext ctx, ulong scopeId, string name)
    {
        foreach (var r in ctx.Db.AuthzRole.ByScopeName.Filter((scopeId, name))) return r.Id;
        return null;
    }

    /// <summary>Create the system role `owner` (`*`) if needed and grant it globally to `who`.</summary>
    public static ulong AuthzBootstrap(ReducerContext ctx, Identity who)
    {
        var owner = AuthzFindRole(ctx, AUTHZ_GLOBAL, "owner") ?? AuthzNewRole(ctx, AUTHZ_GLOBAL, "owner", ["*"], []);
        return AuthzAddGrant(ctx, who, owner, AUTHZ_GLOBAL, null, null);
    }

    /// <summary>Define a system role (clients can't change or delete it). Returns its id.</summary>
    public static ulong AuthzNewRole(ReducerContext ctx, ulong scopeId, string name, List<string> permissions, List<ulong> inherits) =>
        AuthzInsertRole(ctx, scopeId, name, permissions, inherits, true, null);

    /// <summary>Create a scope under `parent` (0 = top level). Returns its id.</summary>
    public static ulong AuthzNewScope(ReducerContext ctx, ulong parent, string kind, string name, Identity? createdBy)
    {
        AuthzCheckName(name);
        AuthzCheckName(kind);
        var path = new List<ulong>();
        if (parent != AUTHZ_GLOBAL)
        {
            var p = ctx.Db.AuthzScope.Id.Find(parent) ?? throw new Exception("no such parent scope");
            path.AddRange(p.Path);
            path.Add(p.Id);
        }
        var s = ctx.Db.AuthzScope.Insert(new AuthzScope
        {
            Id = 0,
            Parent = parent,
            Kind = kind,
            Name = name,
            Path = path,
            CreatedBy = createdBy,
            CreatedAt = ctx.Timestamp,
        });
        AuthzLog(ctx, createdBy, "scope.create", null, 0, s.Id, name);
        // People with grants on the ancestors (or global ones) now reach the new scope too.
        var watch = AuthzWatched(ctx);
        foreach (var who in AuthzHoldersAbove(ctx, s.Id))
        {
            var (held, validUntil) = AuthzCompute(ctx, who, s.Id);
            ctx.Db.AuthzEffective.Insert(new AuthzEffective { Id = 0, Identity = who, ScopeId = s.Id, Perms = held, ValidUntil = validUntil });
            foreach (var w in watch)
            {
                if (w.Length == 0 || held.Any(h => AuthzCovers(h, w)))
                {
                    ctx.Db.AuthzVisible.Insert(new AuthzVisible { Id = 0, Identity = who, ScopeId = s.Id, Perm = w });
                }
            }
        }
        return s.Id;
    }

    /// <summary>Delete a scope, its subtree, and every grant, invite and scoped role in it. Delete your own rows first.</summary>
    public static void AuthzRemoveScope(ReducerContext ctx, ulong scopeId, Identity? by)
    {
        var root = ctx.Db.AuthzScope.Id.Find(scopeId) ?? throw new Exception("no such scope");
        var doomed = AuthzSubtree(ctx, scopeId);
        var affected = new HashSet<Identity>();
        foreach (var s in doomed)
        {
            foreach (var g in ctx.Db.AuthzGrant.ScopeId.Filter(s).ToList())
            {
                affected.Add(g.Identity);
                ctx.Db.AuthzGrant.Id.Delete(g.Id);
            }
            foreach (var inv in ctx.Db.AuthzInvite.ScopeId.Filter(s).ToList()) AuthzDeleteInvite(ctx, inv.Id);
            foreach (var r in ctx.Db.AuthzRole.ScopeId.Filter(s).ToList()) ctx.Db.AuthzRole.Id.Delete(r.Id);
            ctx.Db.AuthzScope.Id.Delete(s);
            foreach (var e in ctx.Db.AuthzEffective.ScopeId.Filter(s).ToList()) affected.Add(e.Identity);
        }
        AuthzLog(ctx, by, "scope.delete", null, 0, root.Parent, root.Name);
        foreach (var who in affected) AuthzRefresh(ctx, who);
    }

    /// <summary>Grant `roleId` to `who` in `scopeId`, optionally until `expiresAt`. Reuses an identical grant.</summary>
    public static ulong AuthzAddGrant(ReducerContext ctx, Identity who, ulong roleId, ulong scopeId, Timestamp? expiresAt, Identity? by)
    {
        var role = ctx.Db.AuthzRole.Id.Find(roleId) ?? throw new Exception("no such role");
        if (scopeId != AUTHZ_GLOBAL && ctx.Db.AuthzScope.Id.Find(scopeId) is null) throw new Exception("no such scope");
        if (!AuthzRoleUsableIn(ctx, role, scopeId)) throw new Exception("that role isn't available in this scope");
        if (expiresAt is { } e && e.MicrosecondsSinceUnixEpoch <= ctx.Timestamp.MicrosecondsSinceUnixEpoch)
        {
            throw new Exception("expiry is in the past");
        }
        ulong id;
        AuthzGrant? existing = null;
        foreach (var g in ctx.Db.AuthzGrant.ByIdentityScope.Filter((who, scopeId)))
        {
            if (g.RoleId == roleId) existing = g;
        }
        if (existing is { } old)
        {
            Timestamp? later = old.ExpiresAt is { } a && expiresAt is { } b
                ? (a.MicrosecondsSinceUnixEpoch >= b.MicrosecondsSinceUnixEpoch ? a : b)
                : null;
            ctx.Db.AuthzGrant.Id.Update(old with { ExpiresAt = later });
            id = old.Id;
        }
        else
        {
            id = ctx.Db.AuthzGrant.Insert(new AuthzGrant
            {
                Id = 0,
                Identity = who,
                RoleId = roleId,
                ScopeId = scopeId,
                GrantedBy = by,
                GrantedAt = ctx.Timestamp,
                ExpiresAt = expiresAt,
            }).Id;
        }
        if (expiresAt is { } at)
        {
            ctx.Db.AuthzJob.Insert(new AuthzJob { ScheduledId = 0, ScheduledAt = new ScheduleAt.Time(at), Kind = 0, Target = id });
        }
        AuthzLog(ctx, by, "grant", who, roleId, scopeId, role.Name);
        AuthzRefresh(ctx, who);
        return id;
    }

    /// <summary>Remove a grant.</summary>
    public static void AuthzRemoveGrant(ReducerContext ctx, ulong grantId, Identity? by)
    {
        var g = ctx.Db.AuthzGrant.Id.Find(grantId) ?? throw new Exception("no such grant");
        ctx.Db.AuthzGrant.Id.Delete(grantId);
        AuthzLog(ctx, by, "revoke", g.Identity, g.RoleId, g.ScopeId, "");
        AuthzRefresh(ctx, g.Identity);
    }

    /// <summary>Recompute authz_effective and authz_visible for everyone (after changing watched permissions).</summary>
    public static void AuthzRefreshAll(ReducerContext ctx)
    {
        var people = new HashSet<Identity>();
        foreach (var g in ctx.Db.AuthzGrant.Iter()) people.Add(g.Identity);
        foreach (var e in ctx.Db.AuthzEffective.Iter()) people.Add(e.Identity);
        foreach (var who in people) AuthzRefresh(ctx, who);
    }

    // -----------------------------------------------------------------------
    // Client reducers (each checks the caller's permissions)
    // -----------------------------------------------------------------------

    [SpacetimeDB.Reducer]
    public static void AuthzCreateScope(ReducerContext ctx, ulong parent, string kind, string name)
    {
        AuthzRequire(ctx, AUTHZ_SCOPE_CREATE, parent);
        AuthzNewScope(ctx, parent, kind, name, ctx.Sender);
    }

    [SpacetimeDB.Reducer]
    public static void AuthzDeleteScope(ReducerContext ctx, ulong scopeId)
    {
        if (scopeId == AUTHZ_GLOBAL) throw new Exception("can't delete the global scope");
        if (!AuthzGetSettings(ctx).ClientsDeleteScopes) throw new Exception("scopes are deleted through this module's own reducers");
        AuthzRequire(ctx, AUTHZ_SCOPE_DELETE, scopeId);
        AuthzRemoveScope(ctx, scopeId, ctx.Sender);
    }

    [SpacetimeDB.Reducer]
    public static void AuthzGrantRole(ReducerContext ctx, Identity identity, ulong roleId, ulong scopeId, Timestamp? expiresAt)
    {
        AuthzCheckDelegate(ctx, AUTHZ_GRANT, roleId, scopeId);
        AuthzAddGrant(ctx, identity, roleId, scopeId, expiresAt, ctx.Sender);
    }

    /// <summary>Revoke a grant: your own (leaving), or one you could have granted.</summary>
    [SpacetimeDB.Reducer]
    public static void AuthzRevokeGrant(ReducerContext ctx, ulong grantId)
    {
        var g = ctx.Db.AuthzGrant.Id.Find(grantId) ?? throw new Exception("no such grant");
        if (g.Identity != ctx.Sender) AuthzCheckDelegate(ctx, AUTHZ_GRANT, g.RoleId, g.ScopeId);
        AuthzRemoveGrant(ctx, grantId, ctx.Sender);
    }

    [SpacetimeDB.Reducer]
    public static void AuthzCreateRole(ReducerContext ctx, ulong scopeId, string name, List<string> permissions, List<ulong> inherits)
    {
        AuthzRequire(ctx, AUTHZ_ROLE, scopeId);
        AuthzInsertRole(ctx, scopeId, name, permissions, inherits, false, ctx.Sender);
    }

    /// <summary>Change a non-system role. You must hold its old and new permissions in its scope.</summary>
    [SpacetimeDB.Reducer]
    public static void AuthzUpdateRole(ReducerContext ctx, ulong roleId, List<string> permissions, List<ulong> inherits)
    {
        var role = ctx.Db.AuthzRole.Id.Find(roleId) ?? throw new Exception("no such role");
        if (role.System) throw new Exception("system roles can only be changed by the module");
        AuthzRequire(ctx, AUTHZ_ROLE, role.ScopeId);
        if (!AuthzHoldsAll(ctx, ctx.Sender, role.Effective, role.ScopeId)) throw new Exception("you can only change roles whose permissions you hold");
        AuthzCheckPerms(permissions);
        AuthzCheckInherits(ctx, role.ScopeId, inherits, roleId);
        var effective = AuthzFlatten(ctx, permissions, inherits);
        if (!AuthzHoldsAll(ctx, ctx.Sender, effective, role.ScopeId)) throw new Exception("you can only give a role permissions you hold");
        ctx.Db.AuthzRole.Id.Update(role with { Permissions = permissions, Inherits = inherits });
        AuthzRecomputeRoles(ctx);
        AuthzLog(ctx, ctx.Sender, "role.update", null, roleId, role.ScopeId, role.Name);
    }

    /// <summary>Delete a non-system role nobody holds or inherits.</summary>
    [SpacetimeDB.Reducer]
    public static void AuthzDeleteRole(ReducerContext ctx, ulong roleId)
    {
        var role = ctx.Db.AuthzRole.Id.Find(roleId) ?? throw new Exception("no such role");
        if (role.System) throw new Exception("system roles can only be deleted by the module");
        AuthzRequire(ctx, AUTHZ_ROLE, role.ScopeId);
        if (!AuthzHoldsAll(ctx, ctx.Sender, role.Effective, role.ScopeId)) throw new Exception("you can only delete roles whose permissions you hold");
        if (ctx.Db.AuthzGrant.RoleId.Filter(roleId).Any()) throw new Exception("role is still granted");
        if (ctx.Db.AuthzRole.Iter().Any(r => r.Inherits.Contains(roleId))) throw new Exception("another role inherits it");
        foreach (var inv in ctx.Db.AuthzInvite.Iter().Where(i => i.RoleId == roleId).ToList()) AuthzDeleteInvite(ctx, inv.Id);
        ctx.Db.AuthzRole.Id.Delete(roleId);
        AuthzLog(ctx, ctx.Sender, "role.delete", null, roleId, role.ScopeId, role.Name);
    }

    /// <summary>Create an invite. Generate the code on the client (16+ random characters) and share it.</summary>
    [SpacetimeDB.Reducer]
    public static void AuthzCreateInvite(ReducerContext ctx, string code, ulong roleId, ulong scopeId, uint maxUses, Timestamp? expiresAt, ulong grantTtlSecs)
    {
        AuthzCheckDelegate(ctx, AUTHZ_INVITE, roleId, scopeId);
        if (code.Length < AuthzMinInviteCode || code.Length > 128) throw new Exception($"invite codes must be {AuthzMinInviteCode}-128 characters");
        if (ctx.Db.AuthzInviteCode.Code.Find(code) is not null) throw new Exception("that code is taken");
        if (expiresAt is { } e && e.MicrosecondsSinceUnixEpoch <= ctx.Timestamp.MicrosecondsSinceUnixEpoch) throw new Exception("expiry is in the past");
        var inv = ctx.Db.AuthzInvite.Insert(new AuthzInvite
        {
            Id = 0,
            RoleId = roleId,
            ScopeId = scopeId,
            CreatedBy = ctx.Sender,
            CreatedAt = ctx.Timestamp,
            ExpiresAt = expiresAt,
            MaxUses = maxUses,
            Uses = 0,
            GrantTtlSecs = grantTtlSecs,
        });
        ctx.Db.AuthzInviteCode.Insert(new AuthzInviteCode { Code = code, InviteId = inv.Id });
        if (expiresAt is { } at) ctx.Db.AuthzJob.Insert(new AuthzJob { ScheduledId = 0, ScheduledAt = new ScheduleAt.Time(at), Kind = 1, Target = inv.Id });
        AuthzLog(ctx, ctx.Sender, "invite.create", null, roleId, scopeId, "");
    }

    [SpacetimeDB.Reducer]
    public static void AuthzRevokeInvite(ReducerContext ctx, ulong inviteId)
    {
        var inv = ctx.Db.AuthzInvite.Id.Find(inviteId) ?? throw new Exception("no such invite");
        if (inv.CreatedBy != ctx.Sender) AuthzCheckDelegate(ctx, AUTHZ_INVITE, inv.RoleId, inv.ScopeId);
        AuthzDeleteInvite(ctx, inviteId);
        AuthzLog(ctx, ctx.Sender, "invite.revoke", null, inv.RoleId, inv.ScopeId, "");
    }

    /// <summary>Redeem an invite code. The inviter must still be allowed to hand out the role.</summary>
    [SpacetimeDB.Reducer]
    public static void AuthzRedeemInvite(ReducerContext ctx, string code)
    {
        var link = ctx.Db.AuthzInviteCode.Code.Find(code) ?? throw new Exception("invalid invite");
        var inv = ctx.Db.AuthzInvite.Id.Find(link.InviteId) ?? throw new Exception("invalid invite");
        if (inv.ExpiresAt is { } e && e.MicrosecondsSinceUnixEpoch <= ctx.Timestamp.MicrosecondsSinceUnixEpoch)
        {
            // Deleting here would be rolled back by the throw; the scheduled job removes it.
            throw new Exception("invite expired");
        }
        var role = ctx.Db.AuthzRole.Id.Find(inv.RoleId) ?? throw new Exception("invalid invite");
        if (!AuthzCan(ctx, inv.CreatedBy, AUTHZ_INVITE, inv.ScopeId) || !AuthzHoldsAll(ctx, inv.CreatedBy, role.Effective, inv.ScopeId))
        {
            throw new Exception("the inviter can no longer grant this role");
        }
        Timestamp? expiresAt = inv.GrantTtlSecs > 0 ? ctx.Timestamp + new TimeDuration((long)inv.GrantTtlSecs * 1_000_000) : null;
        AuthzAddGrant(ctx, ctx.Sender, inv.RoleId, inv.ScopeId, expiresAt, inv.CreatedBy);
        var uses = inv.Uses + 1;
        AuthzLog(ctx, ctx.Sender, "invite.redeem", ctx.Sender, inv.RoleId, inv.ScopeId, "");
        if (inv.MaxUses > 0 && uses >= inv.MaxUses) AuthzDeleteInvite(ctx, inv.Id);
        else ctx.Db.AuthzInvite.Id.Update(inv with { Uses = uses });
    }

    /// <summary>Scheduled: expire a grant or invite on time. Not callable by clients.</summary>
    [SpacetimeDB.Reducer]
    public static void AuthzRunJob(ReducerContext ctx, AuthzJob job)
    {
        if (ctx.Sender != ctx.DatabaseIdentity) throw new Exception("scheduler only");
        if (job.Kind == 0)
        {
            if (ctx.Db.AuthzGrant.Id.Find(job.Target) is { } g && !AuthzLive(g, ctx.Timestamp))
            {
                ctx.Db.AuthzGrant.Id.Delete(g.Id);
                AuthzLog(ctx, null, "expire", g.Identity, g.RoleId, g.ScopeId, "");
                AuthzRefresh(ctx, g.Identity);
            }
        }
        else if (ctx.Db.AuthzInvite.Id.Find(job.Target) is { } inv && inv.ExpiresAt is { } t
                 && t.MicrosecondsSinceUnixEpoch <= ctx.Timestamp.MicrosecondsSinceUnixEpoch)
        {
            AuthzDeleteInvite(ctx, inv.Id);
            AuthzLog(ctx, null, "invite.expire", null, inv.RoleId, inv.ScopeId, "");
        }
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    static void AuthzCheckName(string s)
    {
        if (string.IsNullOrWhiteSpace(s) || s.Length > AuthzMaxName) throw new Exception($"names must be 1-{AuthzMaxName} characters");
    }

    static void AuthzCheckPerms(List<string> perms)
    {
        if (perms.Count > AuthzMaxPerms) throw new Exception($"at most {AuthzMaxPerms} permissions per role");
        foreach (var p in perms)
        {
            var ok = p.Length > 0 && p.Length <= 128
                && p.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '*')
                && (p == "*" || !p.Contains('*') || (p.EndsWith(".*") && !p[..^2].Contains('*')));
            if (!ok) throw new Exception($"bad permission `{p}`: use a.b.c, a.*, or *");
        }
    }

    /// <summary>Inherited roles must exist, be usable in scopeId, and not form a cycle.</summary>
    static void AuthzCheckInherits(ReducerContext ctx, ulong scopeId, List<ulong> inherits, ulong? self)
    {
        foreach (var id in inherits)
        {
            var r = ctx.Db.AuthzRole.Id.Find(id) ?? throw new Exception("inherited role doesn't exist");
            if (!AuthzRoleUsableIn(ctx, r, scopeId)) throw new Exception("inherited role isn't available in this scope");
        }
        if (self is not { } me) return;
        var stack = new Stack<ulong>(inherits);
        var seen = new HashSet<ulong>();
        while (stack.Count > 0)
        {
            var id = stack.Pop();
            if (id == me) throw new Exception("roles can't inherit themselves");
            if (seen.Add(id) && ctx.Db.AuthzRole.Id.Find(id) is { } r) foreach (var x in r.Inherits) stack.Push(x);
        }
    }

    static List<string> AuthzFlatten(ReducerContext ctx, List<string> perms, List<ulong> inherits)
    {
        var out_ = new SortedSet<string>(perms, StringComparer.Ordinal);
        var stack = new Stack<ulong>(inherits);
        var seen = new HashSet<ulong>();
        while (stack.Count > 0)
        {
            var id = stack.Pop();
            if (seen.Add(id) && ctx.Db.AuthzRole.Id.Find(id) is { } r)
            {
                out_.UnionWith(r.Permissions);
                foreach (var x in r.Inherits) stack.Push(x);
            }
        }
        return [.. out_];
    }

    static ulong AuthzInsertRole(ReducerContext ctx, ulong scopeId, string name, List<string> permissions, List<ulong> inherits, bool system, Identity? by)
    {
        AuthzCheckName(name);
        AuthzCheckPerms(permissions);
        if (scopeId != AUTHZ_GLOBAL && ctx.Db.AuthzScope.Id.Find(scopeId) is null) throw new Exception("no such scope");
        if (AuthzFindRole(ctx, scopeId, name) is not null) throw new Exception("a role with that name exists in this scope");
        AuthzCheckInherits(ctx, scopeId, inherits, null);
        var effective = AuthzFlatten(ctx, permissions, inherits);
        if (by is { } who && !AuthzHoldsAll(ctx, who, effective, scopeId)) throw new Exception("you can only give a role permissions you hold");
        var r = ctx.Db.AuthzRole.Insert(new AuthzRole
        {
            Id = 0,
            ScopeId = scopeId,
            Name = name,
            Permissions = permissions,
            Inherits = inherits,
            Effective = effective,
            System = system,
        });
        AuthzLog(ctx, by, "role.create", null, r.Id, scopeId, name);
        return r.Id;
    }

    /// <summary>Re-flatten every role (roles are few), then refresh everyone whose permissions changed.</summary>
    static void AuthzRecomputeRoles(ReducerContext ctx)
    {
        var changed = new List<ulong>();
        foreach (var r in ctx.Db.AuthzRole.Iter().ToList())
        {
            var effective = AuthzFlatten(ctx, r.Permissions, r.Inherits);
            if (!effective.SequenceEqual(r.Effective))
            {
                changed.Add(r.Id);
                ctx.Db.AuthzRole.Id.Update(r with { Effective = effective });
            }
        }
        var people = new HashSet<Identity>();
        foreach (var id in changed) foreach (var g in ctx.Db.AuthzGrant.RoleId.Filter(id)) people.Add(g.Identity);
        foreach (var who in people) AuthzRefresh(ctx, who);
    }

    static void AuthzDeleteInvite(ReducerContext ctx, ulong inviteId)
    {
        ctx.Db.AuthzInvite.Id.Delete(inviteId);
        ctx.Db.AuthzInviteCode.InviteId.Delete(inviteId);
    }

    /// <summary>Everyone with a live grant on scopeId's ancestors, including global ones.</summary>
    static HashSet<Identity> AuthzHoldersAbove(ReducerContext ctx, ulong scopeId)
    {
        var out_ = new HashSet<Identity>();
        foreach (var s in (AuthzLineage(ctx, scopeId) ?? []).Skip(1))
        {
            foreach (var g in ctx.Db.AuthzGrant.ScopeId.Filter(s)) if (AuthzLive(g, ctx.Timestamp)) out_.Add(g.Identity);
        }
        return out_;
    }

    static List<string> AuthzWatched(ReducerContext ctx)
    {
        var w = new List<string> { AUTHZ_MEMBER, AUTHZ_GRANT, AUTHZ_INVITE, AUTHZ_AUDIT };
        foreach (var p in AuthzGetSettings(ctx).Watch) if (!w.Contains(p)) w.Add(p);
        return w;
    }

    /// <summary>
    /// Rebuild who's rows in authz_effective and authz_visible: their flattened permissions in
    /// every scope they reach, and for each watched permission every scope where they hold it.
    /// Grants expand down the tree; a global grant expands to every scope.
    /// </summary>
    static void AuthzRefresh(ReducerContext ctx, Identity who)
    {
        var eff = new Dictionary<ulong, (SortedSet<string> Perms, Timestamp? Until)>();
        var children = new Dictionary<ulong, List<ulong>>();
        foreach (var g in ctx.Db.AuthzGrant.Identity.Filter(who))
        {
            if (!AuthzLive(g, ctx.Timestamp) || ctx.Db.AuthzRole.Id.Find(g.RoleId) is not { } role) continue;
            var scopes = new List<ulong> { g.ScopeId };
            for (var i = 0; i < scopes.Count; i++)
            {
                if (!children.TryGetValue(scopes[i], out var kids))
                {
                    kids = ctx.Db.AuthzScope.Parent.Filter(scopes[i]).Select(c => c.Id).ToList();
                    children[scopes[i]] = kids;
                }
                scopes.AddRange(kids);
            }
            foreach (var s in scopes)
            {
                if (!eff.TryGetValue(s, out var e)) e = (new SortedSet<string>(StringComparer.Ordinal), null);
                e.Perms.UnionWith(role.Effective);
                eff[s] = (e.Perms, AuthzEarliest(e.Until, g.ExpiresAt));
            }
        }

        // authz_effective: one row per reached scope.
        var old = ctx.Db.AuthzEffective.Identity.Filter(who).ToDictionary(e => e.ScopeId);
        foreach (var (scopeId, (set, until)) in eff)
        {
            var perms = set.ToList();
            if (old.Remove(scopeId, out var row))
            {
                var same = row.Perms.SequenceEqual(perms) && row.ValidUntil?.MicrosecondsSinceUnixEpoch == until?.MicrosecondsSinceUnixEpoch;
                if (!same) ctx.Db.AuthzEffective.Id.Update(row with { Perms = perms, ValidUntil = until });
            }
            else
            {
                ctx.Db.AuthzEffective.Insert(new AuthzEffective { Id = 0, Identity = who, ScopeId = scopeId, Perms = perms, ValidUntil = until });
            }
        }
        foreach (var row in old.Values) ctx.Db.AuthzEffective.Id.Delete(row.Id);

        // authz_visible: (scope, watched permission) pairs.
        var watch = AuthzWatched(ctx);
        var want = new HashSet<(ulong, string)>();
        foreach (var (scopeId, (set, _)) in eff)
        {
            foreach (var w in watch) if (w.Length == 0 || set.Any(h => AuthzCovers(h, w))) want.Add((scopeId, w));
        }
        foreach (var row in ctx.Db.AuthzVisible.Identity.Filter(who).ToList())
        {
            if (!want.Remove((row.ScopeId, row.Perm))) ctx.Db.AuthzVisible.Id.Delete(row.Id);
        }
        foreach (var (scopeId, perm) in want)
        {
            ctx.Db.AuthzVisible.Insert(new AuthzVisible { Id = 0, Identity = who, ScopeId = scopeId, Perm = perm });
        }
    }

    static void AuthzLog(ReducerContext ctx, Identity? actor, string action, Identity? target, ulong roleId, ulong scopeId, string detail)
    {
        ctx.Db.AuthzAudit.Insert(new AuthzAudit
        {
            Id = 0,
            At = ctx.Timestamp,
            Actor = actor,
            Action = action,
            Target = target ?? default,
            RoleId = roleId,
            ScopeId = scopeId,
            Detail = detail,
        });
    }
}
