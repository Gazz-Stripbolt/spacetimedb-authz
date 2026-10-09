// One client API over both schema flavours:
//   flat: Rust and C# modules       (tables `authz_grant`, reducers `authz_grant_role`, ...)
//   ns:   the TypeScript submodule  (tables `authz.grants`, reducers `authz.grant_role`, ...)
// Rows, columns and reducer arguments are identical; only the names differ.
import type { Identity, Timestamp } from 'spacetimedb';
import { DbConnection as FlatConnection } from './bindings/index';
import { DbConnection as NsConnection } from './bindings-ns/index';

export type Flavor = 'flat' | 'ns';
type Db = FlatConnection['db'];
export type Conn = FlatConnection;

const NAMES = {
  flat: {
    role: 'authz_role', scope: 'authz_scope', grant: 'authz_grant', invite: 'authz_invite',
    visible: 'authz_visible', audit: 'authz_audit', reducer: (r: string) => `authz_${r}`,
  },
  ns: {
    role: 'authz.roles', scope: 'authz.scopes', grant: 'authz.grants', invite: 'authz.invites',
    visible: 'authz.visible', audit: 'authz.audit', reducer: (r: string) => `authz.${r}`,
  },
} as const;

export interface Authz {
  flavor: Flavor;
  conn: Conn;
  identity: Identity;
  token: string;
  role: Db['authzRole'];
  scope: Db['authzScope'];
  grant: Db['authzGrant'];
  invite: Db['authzInvite'];
  visible: Db['authzVisible'];
  audit: Db['authzAudit'];
  profile: Db['demoProfile'];
  doc: Db['demoDoc'];
  /** SQL names, for subscriptions. */
  sql: { role: string; scope: string; grant: string; invite: string; visible: string; audit: string; profile: string; doc: string };
  /** Subscribe to everything this client is allowed to see. */
  subscribeAll(): Promise<void>;
  // authz reducers
  createScope(parent: bigint, kind: string, name: string): Promise<void>;
  grantRole(identity: Identity, roleId: bigint, scopeId: bigint, expiresAt?: Timestamp): Promise<void>;
  revokeGrant(grantId: bigint): Promise<void>;
  createRole(scopeId: bigint, name: string, permissions: string[], inherits: bigint[]): Promise<void>;
  updateRole(roleId: bigint, permissions: string[], inherits: bigint[]): Promise<void>;
  deleteRole(roleId: bigint): Promise<void>;
  createInvite(code: string, roleId: bigint, scopeId: bigint, maxUses: number, expiresAt: Timestamp | undefined, grantTtlSecs: bigint): Promise<void>;
  revokeInvite(inviteId: bigint): Promise<void>;
  redeemInvite(code: string): Promise<void>;
  // demo reducers
  setName(name: string): Promise<void>;
  createWorkspace(name: string): Promise<void>;
  deleteScope(scopeId: bigint): Promise<void>;
  createDoc(scopeId: bigint, title: string, body: string): Promise<void>;
  updateDoc(id: bigint, body: string): Promise<void>;
  deleteDoc(id: bigint): Promise<void>;
  bench(scopeId: bigint, n: number): Promise<void>;
}

export function connect(flavor: Flavor, host: string, db: string, token?: string, onDisconnect?: () => void): Promise<Authz> {
  const Builder = flavor === 'ns' ? NsConnection : FlatConnection;
  return new Promise((resolve, reject) => {
    Builder.builder()
      .withUri(host)
      .withDatabaseName(db)
      .withToken(token)
      .onConnect((c, identity, tok) => resolve(wrap(flavor, c as unknown as Conn, identity, tok)))
      .onDisconnect(() => onDisconnect?.())
      .onConnectError((_c, e) => reject(e))
      .build();
  });
}

/** Reducer accessor names: `authz_grant_role` → `authzGrantRole`, `authz.grant_role` → `authz.grantRole`. */
const camel = (s: string) => s.replace(/_([a-z])/g, (_m, c) => c.toUpperCase());

function wrap(flavor: Flavor, conn: Conn, identity: Identity, token: string): Authz {
  const n = NAMES[flavor];
  const d = conn.db as any;
  const r = conn.reducers as any;
  const tbl = (name: string) => d[flavor === 'ns' ? name : camel(name)];
  const red = (name: string) => r[camel(n.reducer(name))];
  const sql = { role: n.role, scope: n.scope, grant: n.grant, invite: n.invite, visible: n.visible, audit: n.audit, profile: 'demo_profile', doc: 'demo_doc' };
  return {
    flavor,
    conn,
    identity,
    token,
    role: tbl(n.role),
    scope: tbl(n.scope),
    grant: tbl(n.grant),
    invite: tbl(n.invite),
    visible: tbl(n.visible),
    audit: tbl(n.audit),
    profile: d.demoProfile,
    doc: d.demoDoc,
    sql,
    subscribeAll: () =>
      new Promise((res, rej) =>
        conn
          .subscriptionBuilder()
          .onApplied(() => res())
          .onError((ctx) => rej((ctx as { event?: Error }).event ?? new Error('subscription failed')))
          .subscribe(Object.values(sql).map((t) => `SELECT * FROM ${t}`))
      ),
    createScope: (parent, kind, name) => red('create_scope')({ parent, kind, name }),
    grantRole: (identity, roleId, scopeId, expiresAt) => red('grant_role')({ identity, roleId, scopeId, expiresAt }),
    revokeGrant: (grantId) => red('revoke_grant')({ grantId }),
    createRole: (scopeId, name, permissions, inherits) => red('create_role')({ scopeId, name, permissions, inherits }),
    updateRole: (roleId, permissions, inherits) => red('update_role')({ roleId, permissions, inherits }),
    deleteRole: (roleId) => red('delete_role')({ roleId }),
    createInvite: (code, roleId, scopeId, maxUses, expiresAt, grantTtlSecs) =>
      red('create_invite')({ code, roleId, scopeId, maxUses, expiresAt, grantTtlSecs }),
    revokeInvite: (inviteId) => red('revoke_invite')({ inviteId }),
    redeemInvite: (code) => red('redeem_invite')({ code }),
    setName: (name) => r.demoSetName({ name }),
    createWorkspace: (name) => r.demoCreateWorkspace({ name }),
    deleteScope: (scopeId) => r.demoDeleteScope({ scopeId }),
    createDoc: (scopeId, title, body) => r.demoCreateDoc({ scopeId, title, body }),
    updateDoc: (id, body) => r.demoUpdateDoc({ id, body }),
    deleteDoc: (id) => r.demoDeleteDoc({ id }),
    bench: (scopeId, n) => r.demoBench({ scopeId, n }),
  };
}
