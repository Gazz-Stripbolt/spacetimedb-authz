# Findings

What we learned building authorization on SpacetimeDB 2.11: one bug, a few row-level-security (RLS) limits, privacy
tradeoffs and numbers.

## Bug: a second RLS rule breaks live updates from a join rule (reported: [#6125](https://github.com/clockworklabs/SpacetimeDB/issues/6125))

When a table has **two** RLS rules (they're OR'd) and one of them is a join, rows that match only the join rule show up
in the initial subscription but **never arrive as live inserts**. A rule on the table's own columns keeps working live.

Minimal repro (Rust, `unstable` feature):

```rust
#[spacetimedb::table(accessor = visible, public)]
pub struct Visible { #[primary_key] #[auto_inc] id: u64, #[index(btree)] identity: Identity, #[index(btree)] scope_id: u64 }

#[spacetimedb::table(accessor = two_rules, public)]
pub struct TwoRules { #[primary_key] #[auto_inc] id: u64, #[index(btree)] scope_id: u64, target: Identity }

#[client_visibility_filter]
const A: Filter = Filter::Sql("SELECT two_rules.* FROM two_rules JOIN visible ON two_rules.scope_id = visible.scope_id WHERE visible.identity = :sender");
#[client_visibility_filter]
const B: Filter = Filter::Sql("SELECT * FROM two_rules WHERE two_rules.target = :sender");
```

A client inserts `visible(me, 7)`, subscribes to `SELECT * FROM two_rules`, then a reducer inserts
`two_rules(scope 7, target ZERO)` and `two_rules(scope 999, target me)`. Live, the client receives only the scope-999
row (rule B). A fresh subscription returns both. The same table with only rule A delivers live correctly.

Workaround: **one rule per table.** That's why members see the scope's roster (one membership rule) rather than "own
grants + grants I manage", and why the audit log is visible to `authz.audit` holders only.

## RLS limits we designed around

Reported upstream: [#6129](https://github.com/clockworklabs/SpacetimeDB/issues/6129) (joined table with its own rule), [#6128](https://github.com/clockworklabs/SpacetimeDB/issues/6128) (the docs' cross-join example), [#2830](https://github.com/clockworklabs/SpacetimeDB/issues/2830) (private joined table).

1. **The joined table must be public and have no RLS of its own.** For a private table the subscription fails with
   `no such table … may be marked private`. If it has its own rule (e.g. `visible WHERE identity = :sender`), every
   subscription to the protected table fails with `Subscriptions require indexes on join columns`, even with indexes
   everywhere. This holds for regular tables, not only event tables (the voip repo hit it with event tables). So
   `authz_visible` is public.
2. **Cross joins don't work in subscriptions.** The docs' own example shape, `SELECT t.* FROM t JOIN admin WHERE
   admin.identity = :sender` (no `ON`), fails at subscribe time with `Subscriptions require indexes on join columns`.
   We wanted that for global grants ("see everything"). Instead, global grants are expanded to a row per scope.
3. **`:sender` can't be compared with an `Option<Identity>` column.** The publish fails: `failed to create row-level
   security … Unexpected type: (expected) (__identity__: U256) != (some: … | none: ())`. So `authz_audit.target` is a
   plain `Identity` that uses the zero identity for "nobody".
4. **Access changes are live.** Inserting or deleting rows in the joined table (`authz_visible`) correctly adds or
   removes the protected rows on subscribed clients: grant `viewer` and the docs appear; revoke it and they disappear.
5. **The module owner bypasses RLS** and sees every row. Test with other identities.

## Privacy

What each table reveals to whom:

| Table | Who sees a row |
|---|---|
| `authz_role` | everyone (role definitions) |
| `authz_scope` | members of the scope (any grant on it or above) |
| `authz_grant` | members of the grant's scope (the roster: who holds which role, granted by whom, until when) |
| `authz_invite` | holders of `authz.invite` in the scope; the codes themselves are private |
| `authz_audit` | holders of `authz.audit` in the scope |
| `authz_visible` | **everyone** |
| your tables | holders of the watched permission (e.g. `doc.read`) |

`authz_visible` is the leak: anyone can see which identities hold which *watched* permissions in which *scope ids*.
Scope ids are auto-incremented numbers, and names, roles and data stay hidden, but membership patterns ("these five
identities share scope 42") are public. Keep the watch list short. If even that's too much, skip RLS for your tables
and serve reads through procedures that call `can()`.

## Things worth knowing

- **Clients can call scheduled reducers.** `spacetime call db authz_run_job '[1, {"Time":[0]}, 0, 1]'` reaches the
  reducer in 2.11. Every scheduled reducer here checks `ctx.sender() == ctx.database_identity()` first. (Rust's
  `ctx.identity()` is deprecated in favour of `database_identity()`.)
- **Table accessors and reducers share a namespace in Rust.** A table `accessor = authz_grant` and a reducer
  `fn authz_grant` don't compile (`E0428: the name authz_grant is defined multiple times`), because the table macro
  generates a trait with that name. So the reducers are verb-first (`authz_grant_role`).
- **Writes before an error are rolled back.** "Delete the expired invite, then return an error" deletes nothing. Expiry
  cleanup lives in the scheduled job instead.
- **Exact expiry with one-shot schedules.** Every expiring grant or invite gets a `ScheduleAt::Time` job at its expiry,
  so it disappears on time (and from RLS). Checks don't depend on the job running: a cached permission set carries its
  earliest expiry, and past it, `can()` falls back to walking live grants.
- **C# `[SpacetimeDB.Type]` structs' generated `Equals(object)` recurses forever** (found in the voip repo). Authz.cs
  never calls it.

## Numbers

`tests/bench.mts` times `demo_bench(scope, n)`, which runs `n` checks in one reducer (half allowed, half denied) against
a 3-level scope tree, with grants for the caller at all three levels. Measured on a 2-vCPU VM:

| | Walking grants (first version) | Precomputed `authz_effective` |
|---|---|---|
| Rust | 10.4 µs per check | **2.2 µs** (~460k checks/s) |
| C# (NativeAOT-LLVM) | 48.8 µs | **8.6 µs** |
| TypeScript | | **2.7 µs** |

The walk does a scope lookup, then an index probe per ancestor and a role lookup per matching grant, deserialising
permission lists each time. The precomputed table makes it one probe plus a string match. The cost moves to writes:
granting, revoking or changing a role rebuilds that identity's rows (proportional to the scopes they reach), and creating
a scope adds a row for each holder above it. Global grants reach every scope, so keep them rare.
