// Demo: a team workspace. Anyone can create a workspace (and is its admin); admins add projects,
// invite people, define roles and hand them out; docs are visible only to people with doc.read
// there. Serves the web client at /route/. The C# twin of demo/rust.

#pragma warning disable STDB_UNSTABLE

using SpacetimeDB;

public static partial class Module
{
    [SpacetimeDB.Table(Accessor = "DemoProfile", Public = true)]
    public partial struct DemoProfile
    {
        [SpacetimeDB.PrimaryKey]
        public Identity Identity;
        public string Name;
    }

    [SpacetimeDB.Table(Accessor = "DemoDoc", Public = true)]
    public partial struct DemoDoc
    {
        [SpacetimeDB.PrimaryKey, SpacetimeDB.AutoInc]
        public ulong Id;
        [SpacetimeDB.Index.BTree]
        public ulong ScopeId;
        public string Title;
        public string Body;
        public Identity Author;
        public Timestamp UpdatedAt;
    }

    /// <summary>Docs are visible to people holding doc.read in the doc's scope (or above it).</summary>
    [SpacetimeDB.ClientVisibilityFilter]
    public static readonly Filter DEMO_DOC_READ = AuthzRls("demo_doc", "scope_id", "doc.read");

    [SpacetimeDB.Reducer(ReducerKind.Init)]
    public static void Init(ReducerContext ctx)
    {
        AuthzConfigure(ctx, new AuthzSettings { Watch = ["doc.read"], ClientsDeleteScopes = false });
        AuthzBootstrap(ctx, ctx.Sender);
        var viewer = AuthzNewRole(ctx, AUTHZ_GLOBAL, "viewer", ["doc.read"], []);
        var editor = AuthzNewRole(ctx, AUTHZ_GLOBAL, "editor", ["doc.write"], [viewer]);
        AuthzNewRole(ctx, AUTHZ_GLOBAL, "admin",
            ["doc.delete", "authz.grant", "authz.invite", "authz.role", "authz.scope.create", "authz.scope.delete", "authz.audit"], [editor]);
    }

    [SpacetimeDB.Reducer(ReducerKind.ClientConnected)]
    public static void Connected(ReducerContext ctx)
    {
        if (ctx.Db.DemoProfile.Identity.Find(ctx.Sender) is null)
        {
            var hex = ctx.Sender.ToString();
            ctx.Db.DemoProfile.Insert(new DemoProfile { Identity = ctx.Sender, Name = $"guest-{hex[^4..]}" });
        }
    }

    [SpacetimeDB.Reducer]
    public static void DemoSetName(ReducerContext ctx, string name)
    {
        name = name.Trim();
        if (name.Length is 0 or > 24) throw new Exception("name must be 1-24 characters");
        ctx.Db.DemoProfile.Identity.Update(new DemoProfile { Identity = ctx.Sender, Name = name });
    }

    /// <summary>Anyone can start a workspace; the module makes them its admin.</summary>
    [SpacetimeDB.Reducer]
    public static void DemoCreateWorkspace(ReducerContext ctx, string name)
    {
        var ws = AuthzNewScope(ctx, AUTHZ_GLOBAL, "workspace", name.Trim(), ctx.Sender);
        var admin = AuthzFindRole(ctx, AUTHZ_GLOBAL, "admin") ?? throw new Exception("admin role missing");
        AuthzAddGrant(ctx, ctx.Sender, admin, ws, null, null);
    }

    /// <summary>Delete a workspace or project: its docs first, then the scopes, grants and invites.</summary>
    [SpacetimeDB.Reducer]
    public static void DemoDeleteScope(ReducerContext ctx, ulong scopeId)
    {
        AuthzRequire(ctx, AUTHZ_SCOPE_DELETE, scopeId);
        foreach (var s in AuthzSubtree(ctx, scopeId))
        {
            foreach (var d in ctx.Db.DemoDoc.ScopeId.Filter(s).ToList()) ctx.Db.DemoDoc.Id.Delete(d.Id);
        }
        AuthzRemoveScope(ctx, scopeId, ctx.Sender);
    }

    [SpacetimeDB.Reducer]
    public static void DemoCreateDoc(ReducerContext ctx, ulong scopeId, string title, string body)
    {
        AuthzRequire(ctx, "doc.write", scopeId);
        title = title.Trim();
        if (title.Length is 0 or > 80 || body.Length > 4000) throw new Exception("title 1-80 characters, body up to 4000");
        ctx.Db.DemoDoc.Insert(new DemoDoc { Id = 0, ScopeId = scopeId, Title = title, Body = body, Author = ctx.Sender, UpdatedAt = ctx.Timestamp });
    }

    [SpacetimeDB.Reducer]
    public static void DemoUpdateDoc(ReducerContext ctx, ulong id, string body)
    {
        var doc = ctx.Db.DemoDoc.Id.Find(id) ?? throw new Exception("no such doc");
        AuthzRequire(ctx, "doc.write", doc.ScopeId);
        if (body.Length > 4000) throw new Exception("body up to 4000");
        ctx.Db.DemoDoc.Id.Update(doc with { Body = body, UpdatedAt = ctx.Timestamp });
    }

    [SpacetimeDB.Reducer]
    public static void DemoDeleteDoc(ReducerContext ctx, ulong id)
    {
        var doc = ctx.Db.DemoDoc.Id.Find(id) ?? throw new Exception("no such doc");
        AuthzRequire(ctx, "doc.delete", doc.ScopeId);
        ctx.Db.DemoDoc.Id.Delete(id);
    }

    /// <summary>Benchmark: n permission checks for the caller in scopeId.</summary>
    [SpacetimeDB.Reducer]
    public static void DemoBench(ReducerContext ctx, ulong scopeId, uint n)
    {
        uint yes = 0;
        for (uint i = 0; i < n; i++)
        {
            if (AuthzCan(ctx, ctx.Sender, i % 2 == 0 ? "doc.write" : "doc.nope", scopeId)) yes++;
        }
        Log.Info($"demo_bench: {yes}/{n} allowed");
    }

    static readonly Lazy<byte[]> DemoPage = new(() =>
    {
        using var s = typeof(Module).Assembly.GetManifestResourceStream("index.html")!;
        using var m = new MemoryStream();
        s.CopyTo(m);
        return m.ToArray();
    });

    [SpacetimeDB.HttpHandler]
    public static HttpResponse Page(HandlerContext ctx, HttpRequest req) =>
        new(200, HttpVersion.Http11,
            new List<HttpHeader> { new("content-type", "text/html; charset=utf-8"), new("cache-control", "no-cache") },
            new HttpBody(DemoPage.Value));

    [SpacetimeDB.HttpRouter]
    public static Router Routes() => Router.New().Get("/", Handlers.Page);
}
