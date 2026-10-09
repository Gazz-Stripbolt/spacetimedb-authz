# spacetimedb-authz for TypeScript (submodule)

Roles, scopes and grants as a **SpacetimeDB submodule**. Source: [`src/index.ts`](src/index.ts) · Complete example:
[`demo/typescript`](../demo/typescript/src/index.ts) · Protocol: [`docs/PROTOCOL.md`](../docs/PROTOCOL.md)

## Install

It isn't on npm yet. Copy this folder into your repo and add it as an npm workspace package, so there's only one
copy of the `spacetimedb` package:

```jsonc
// package.json at your repo root
{ "private": true, "workspaces": ["spacetimedb-authz", "my-module"] }
// my-module/package.json
{ "dependencies": { "spacetimedb": "2.11.*", "spacetimedb-authz": "0.1.0" } }
```

## Wire it up

Submodules can't declare row-level-security filters or an init reducer, so your module adds them:

```typescript
import { schema } from 'spacetimedb/server';
import * as authz from 'spacetimedb-authz';            // `import * as`, not a default import

const spacetimedb = schema({ doc, authz });             // mounted under the namespace "authz"
export default spacetimedb;

const rls = authz.rlsSql('authz');                      // the canonical namespace
export const authzGrants = spacetimedb.clientVisibilityFilter.sql(rls.grants);
export const authzScopes = spacetimedb.clientVisibilityFilter.sql(rls.scopes);
export const authzInvites = spacetimedb.clientVisibilityFilter.sql(rls.invites);
export const authzAudit = spacetimedb.clientVisibilityFilter.sql(rls.audit);
export const docRead = spacetimedb.clientVisibilityFilter.sql(authz.rlsFor('doc', 'scope_id', 'doc.read', 'authz'));

export const init = spacetimedb.init((ctx) => {
  authz.configure(ctx.as.authz, { watch: ['doc.read'], clientsDeleteScopes: false });
  authz.bootstrap(ctx.as.authz, ctx.sender);
  const viewer = authz.newRole(ctx.as.authz, authz.GLOBAL, 'viewer', ['doc.read'], []);
  authz.newRole(ctx.as.authz, authz.GLOBAL, 'editor', ['doc.write'], [viewer]);
});

// in a reducer
authz.require(ctx.as.authz, 'doc.write', doc.scopeId);
```

Library functions: `configure`, `bootstrap`, `newRole`, `newScope`, `removeScope`, `subtree`, `addGrant`,
`removeGrant`, `can`, `require`, `permissions`, `findRole`, `covers`, `refreshAll`.

## Names

Submodule tables and reducers are namespaced: `authz.grants`, reducer `authz.grant_role`, and in generated client
bindings `conn.db['authz.grants']`, `conn.reducers['authz.grantRole']`. Rust and C# use `authz_grant` /
`authz_grant_role`. Columns and arguments are identical. [`demo/web/src/api.ts`](../demo/web/src/api.ts) shows one
client handling both.
