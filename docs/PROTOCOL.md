# Protocol

The tables, reducers and rules a client sees. All three implementations ([`authz.rs`](../rust/authz.rs),
[`Authz.cs`](../csharp/Authz.cs) and the [TypeScript submodule](../typescript/src/index.ts)) expose the same schema;
only the names differ for the submodule.

## Names

| | Rust / C# (flat) | TypeScript submodule mounted as `authz` |
|---|---|---|
| Tables | `authz_role`, `authz_scope`, `authz_grant`, `authz_invite`, `authz_visible`, `authz_audit` | `authz.roles`, `authz.scopes`, `authz.grants`, `authz.invites`, `authz.visible`, `authz.audit` |
| Reducers | `authz_grant_role`, `authz_revoke_grant`, … | `authz.grant_role`, `authz.revoke_grant`, … |

Private tables (never visible to clients): `authz_config`, `authz_invite_code`, `authz_effective`, `authz_job`
(submodule: `config`, `invite_codes`, `effective`, `jobs`). [`demo/web/src/api.ts`](../demo/web/src/api.ts) is one client
covering both naming schemes.

## Permissions

- Dotted strings of `[A-Za-z0-9._-]`: `doc.read`, `billing.refund`.
- `a.*` covers every permission under `a.` (`a.b`, `a.b.c`, and `a.*` itself). `*` covers everything.
- A wildcard is only allowed as the whole permission or as a trailing `.*`.

Permissions the module itself checks:

| Permission | Lets you, in a scope and below |
|---|---|
| `authz.grant` | grant and revoke roles whose permissions you hold |
| `authz.invite` | create and revoke invites for roles whose permissions you hold |
| `authz.role` | define, change and delete (non-system) roles, with permissions you hold |
| `authz.scope.create` | create child scopes |
| `authz.scope.delete` | delete scopes (through the host module's reducer, or `authz_delete_scope` if enabled) |
| `authz.audit` | see the audit log (row-level security) |

## Public tables

### `authz_role`

| Column | Type | |
|---|---|---|
| `id` | u64 PK | |
| `scope_id` | u64 | 0 = usable everywhere; otherwise in that scope and below |
| `name` | string | unique per scope |
| `permissions` | string[] | as defined |
| `inherits` | u64[] | role ids |
| `effective` | string[] | permissions + everything inherited, flattened, sorted |
| `system` | bool | defined by module code; clients can't change or delete it |

Visible to everyone (definitions aren't secret).

### `authz_scope`

| Column | Type | |
|---|---|---|
| `id` | u64 PK | 0 is the implicit global scope (no row) |
| `parent` | u64 | 0 = top level |
| `kind`, `name` | string | |
| `path` | u64[] | ancestors, root first (not including 0 or the scope itself) |
| `created_by` | Option\<Identity\> | |
| `created_at` | Timestamp | |

Visible if you have any grant on the scope or above it.

### `authz_grant`

| Column | Type | |
|---|---|---|
| `id` | u64 PK | |
| `identity` | Identity | |
| `role_id`, `scope_id` | u64 | |
| `granted_by` | Option\<Identity\> | None = module code |
| `granted_at` | Timestamp | |
| `expires_at` | Option\<Timestamp\> | removed by a scheduled job at exactly this time |

Visible to members of the grant's scope (the roster).

### `authz_invite`

`id`, `role_id`, `scope_id`, `created_by`, `created_at`, `expires_at`, `max_uses` (0 = unlimited), `uses`,
`grant_ttl_secs` (0 = permanent grants). The code itself is private. Visible to people holding `authz.invite` in the
scope.

### `authz_visible`

`id`, `identity`, `scope_id`, `perm`. For every identity: one row per (scope, watched permission) they hold there,
expanded down the tree. `perm = ''` means "has any grant here" (membership). The watched permissions are `''`,
`authz.grant`, `authz.invite`, `authz.audit`, plus the module's `watch` list. **Public, with no RLS** (see
[FINDINGS](FINDINGS.md#privacy)).

### `authz_audit`

`id`, `at`, `actor` (None = module/scheduler), `action`, `target` (zero identity = none), `role_id`, `scope_id`,
`detail`.

Actions: `grant`, `revoke`, `expire`, `role.create`, `role.update`, `role.delete`, `invite.create`, `invite.revoke`,
`invite.redeem`, `invite.expire`, `scope.create`, `scope.delete`. Visible to people holding `authz.audit` in the scope.

## Row-level security rules

One rule per table, each joining `authz_visible`:

```sql
-- authz_grant (roster), authz_scope, authz_invite, authz_audit
SELECT authz_grant.* FROM authz_grant JOIN authz_visible ON authz_grant.scope_id = authz_visible.scope_id
WHERE authz_visible.identity = :sender AND authz_visible.perm = ''
-- … same shape: authz_scope ON id / perm '', authz_invite / 'authz.invite', authz_audit / 'authz.audit'

-- your tables (authz_rls! / AuthzRls / rlsFor)
SELECT doc.* FROM doc JOIN authz_visible ON doc.scope_id = authz_visible.scope_id
WHERE authz_visible.identity = :sender AND authz_visible.perm = 'doc.read'
```

## Client reducers

| Reducer | Args | Needs |
|---|---|---|
| `authz_create_scope` | `parent: u64, kind, name` | `authz.scope.create` on parent |
| `authz_delete_scope` | `scope_id: u64` | `clients_delete_scopes` enabled + `authz.scope.delete` |
| `authz_grant_role` | `identity, role_id, scope_id, expires_at: Option<Timestamp>` | `authz.grant` + every permission of the role, in the scope |
| `authz_revoke_grant` | `grant_id` | your own grant (leaving), or what `authz_grant_role` needs for that grant |
| `authz_create_role` | `scope_id, name, permissions: string[], inherits: u64[]` | `authz.role` + every resulting permission |
| `authz_update_role` | `role_id, permissions, inherits` | `authz.role` + the role's old and new permissions; not system roles |
| `authz_delete_role` | `role_id` | as update; the role must not be granted or inherited |
| `authz_create_invite` | `code (16-128 chars), role_id, scope_id, max_uses: u32, expires_at: Option<Timestamp>, grant_ttl_secs: u64` | `authz.invite` + every permission of the role |
| `authz_revoke_invite` | `invite_id` | its creator, or what creating it needs |
| `authz_redeem_invite` | `code` | a valid code, and the inviter must still be able to hand out the role |

Errors are plain strings: `permission denied: <perm>`, `you can only hand out roles whose permissions you hold`,
`invalid invite`, `invite expired`, `the inviter can no longer grant this role`, `role is still granted`, …

Generate invite codes on the client from a cryptographic RNG. Module RNGs are seeded from the transaction timestamp
and shouldn't be used for secrets.
