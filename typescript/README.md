# spacetimedb-authz for TypeScript (submodule)

Roles, scopes and grants as a **Spacetime submodule**. Source: [`src/index.ts`](src/index.ts) · Complete example:
[`demo/typescript`](../demo/typescript/src/index.ts) · Protocol: [`docs/PROTOCOL.md`](../docs/PROTOCOL.md)

## Install

```bash
npm install @pogly/spacetimedb-authz spacetimedb
```

Use `spacetimedb` 2.13.x or 2.14.x, and keep only one copy of it in your module's dependency tree. With two copies,
`spacetime publish` fails with *"Local module schema inspection failed"*. The package ships compiled JavaScript plus
its TypeScript source, which is where the types come from.

A module built with the 2.14 library needs a 2.14 or newer host: the library's HTTP handler export changed, and older
hosts reject it ([release notes](https://github.com/clockworklabs/SpacetimeDB/releases/tag/v2.14.0)). If your host is still on 2.13, stay on `spacetimedb` 2.13.x.

To work on it from a clone instead, add this folder to your npm workspaces next to your module:

```jsonc
// package.json at your repo root
{ "private": true, "workspaces": ["spacetimedb-authz/typescript", "my-module"] }
// my-module/package.json
{ "dependencies": { "spacetimedb": "2.14.*", "@pogly/spacetimedb-authz": "*" } }
```

## Wire it up

Submodules can't declare row-level-security filters or an init reducer, so your module adds them:

```typescript
import { schema } from 'spacetimedb/server';
import * as authz from '@pogly/spacetimedb-authz';            // `import * as`, not a default import

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
