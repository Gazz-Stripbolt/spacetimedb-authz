# Authz.cs: roles, scopes and grants for C# modules

One file. Add [`Authz.cs`](Authz.cs) to your module project (or link it, like
[`demo/csharp/StdbModule.csproj`](../demo/csharp/StdbModule.csproj) does). It uses row-level security, so the file
starts with `#pragma warning disable STDB_UNSTABLE`.

```csharp
[Reducer(ReducerKind.Init)]
public static void Init(ReducerContext ctx)
{
    AuthzConfigure(ctx, new AuthzSettings { Watch = ["doc.read"] });
    AuthzBootstrap(ctx, ctx.Sender);
    var viewer = AuthzNewRole(ctx, AUTHZ_GLOBAL, "viewer", ["doc.read"], []);
    AuthzNewRole(ctx, AUTHZ_GLOBAL, "editor", ["doc.write"], [viewer]);
}

[ClientVisibilityFilter]
public static readonly Filter DOC_READ = AuthzRls("doc", "scope_id", "doc.read");

// in a reducer
AuthzRequire(ctx, "doc.write", doc.ScopeId);
```

A complete module is in [`demo/csharp`](../demo/csharp/Lib.cs). It builds with NativeAOT-LLVM (.NET 10), and
`Authz.cs` also builds on net8.

Library functions: `AuthzConfigure`, `AuthzBootstrap`, `AuthzNewRole`, `AuthzNewScope`, `AuthzRemoveScope`,
`AuthzSubtree`, `AuthzAddGrant`, `AuthzRemoveGrant`, `AuthzCan`, `AuthzRequire`, `AuthzPermissions`, `AuthzFindRole`,
`AuthzCovers`, `AuthzRefreshAll`. The client reducers are the same as Rust (`authz_grant_role`, …); C# canonicalises to
the same names, so the same clients work with both.
