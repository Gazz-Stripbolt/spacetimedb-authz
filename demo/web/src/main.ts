// Demo web client: a team workspace on spacetimedb-authz.
// Served by the demo module at /route/, or open dist/index.html with ?host=ws://...&db=...
import { Timestamp, type Identity } from 'spacetimedb';
import { connect, type Authz, type Flavor } from './api';

const params = new URLSearchParams(location.search);
const routed = location.pathname.match(/\/v1\/database\/([^/]+)\/route/);
const HOST = params.get('host') ?? (routed ? location.origin.replace(/^http/, 'ws') : 'ws://127.0.0.1:3000');
const DB = params.get('db') ?? (routed ? decodeURIComponent(routed[1]) : 'authz-rust');
// Schema flavour: 'flat' (Rust, C#) or 'ns' (TypeScript submodule). The TS demo module serves
// this page with data-flavor="ns"; for a static copy, pass ?flavor=ns.
const FLAVOR = (params.get('flavor') ?? document.documentElement.dataset.flavor ?? 'flat') as Flavor;
const TOKEN_KEY = `authz-demo:${HOST}:${DB}`;
const PERMS = ['doc.read', 'doc.write', 'doc.delete', 'authz.grant', 'authz.invite', 'authz.role', 'authz.scope.create', 'authz.scope.delete', 'authz.audit'];

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
function h(tag: string, props: Record<string, any> = {}, ...kids: (Node | string | null | undefined | false)[]) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k.startsWith('on')) (e as any)[k] = v;
    else if (k === 'class') e.className = v;
    else if (v !== undefined && v !== false) e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const k of kids) if (k) e.append(k);
  return e;
}
const svg = (d: string) => {
  const s = document.createElement('span');
  s.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
  return s.firstElementChild as Element;
};
const ICON: Record<string, string> = {
  workspace: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18"/>',
  project: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
};

function token(): string | undefined {
  if (params.has('fresh')) return undefined;
  try {
    return localStorage.getItem(TOKEN_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}
function status(text: string, ok = true) {
  $('status').textContent = text;
  $('status').classList.toggle('bad', !ok);
}
let toastTimer: ReturnType<typeof setTimeout>;
function toast(text: string, bad = false) {
  const t = $('toast');
  t.textContent = text;
  t.classList.toggle('bad', bad);
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}
async function call(p: Promise<unknown>, ok?: string) {
  try {
    await p;
    if (ok) toast(ok);
    return true;
  } catch (e) {
    toast(String((e as Error)?.message ?? e), true);
    return false;
  }
}

// -- connection ------------------------------------------------------------------

let a: Authz;
try {
  a = await connect(FLAVOR, HOST, DB, token(), () => status('disconnected', false));
} catch (e) {
  status(`can't connect: ${e}`, false);
  throw e;
}
const me: Identity = a.identity;
try {
  localStorage.setItem(TOKEN_KEY, a.token);
} catch {}
if (params.has('test')) Object.assign(window, { __a: a });
status(`connected to ${DB}`);
await a.subscribeAll();

let current = 0n;
let tab = 'docs';
let lastInvite = '';
let pendingSelect: ((s: { id: bigint; name: string }) => boolean) | null = null;

let queued = false;
function queue() {
  if (queued) return;
  queued = true;
  requestAnimationFrame(() => {
    queued = false;
    render();
  });
}
for (const t of [a.scope, a.grant, a.role, a.invite, a.audit, a.doc, a.profile] as any[]) {
  t.onInsert(queue);
  t.onDelete(queue);
  t.onUpdate?.(queue);
}

const invite = params.get('invite');
if (invite) {
  history.replaceState(null, '', location.pathname + location.search.replace(/[?&]invite=[^&]*/, '').replace(/^&/, '?'));
  await call(a.redeemInvite(invite), 'Invite accepted, welcome!');
}

// -- model helpers -----------------------------------------------------------------

const nameOf = (id: Identity) => (id.isEqual(me) ? 'you' : a.profile.identity.find(id)?.name ?? id.toHexString().slice(-6));
const scopeOf = (id: bigint) => [...a.scope.iter()].find((s) => s.id === id);
const lineage = (id: bigint): bigint[] => {
  const s = scopeOf(id);
  return s ? [id, ...[...s.path].reverse(), 0n] : [0n];
};
const live = (g: { expiresAt?: Timestamp }) => !g.expiresAt || g.expiresAt.microsSinceUnixEpoch > BigInt(Date.now()) * 1000n;
const roleOf = (id: bigint) => [...a.role.iter()].find((r) => r.id === id);
const covers = (held: string, want: string) =>
  held === '*' || held === want || (held.endsWith('.*') && want.startsWith(held.slice(0, -1)) && want.length > held.length - 1);
function myGrantsHere(scope: bigint) {
  const chain = lineage(scope);
  return [...a.grant.iter()].filter((g) => g.identity.isEqual(me) && chain.includes(g.scopeId) && live(g));
}
function myPerms(scope: bigint): string[] {
  const out = new Set<string>();
  for (const g of myGrantsHere(scope)) for (const p of roleOf(g.roleId)?.effective ?? []) out.add(p);
  return [...out].sort();
}
const iCan = (perm: string, scope: bigint) => myPerms(scope).some((p) => covers(p, perm));
const usableRoles = (scope: bigint) => {
  const chain = lineage(scope);
  return [...a.role.iter()].filter((r) => chain.includes(r.scopeId)).sort((x, y) => Number(x.id - y.id));
};
const fmtTime = (t: Timestamp) => new Date(Number(t.microsSinceUnixEpoch / 1000n)).toLocaleString();
const inSecs = (s: number) => new Timestamp(BigInt(Date.now() + s * 1000) * 1000n);
function randomCode() {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

// -- rendering -----------------------------------------------------------------------

/** Live updates re-render everything, so form fields carry a `keep` key and survive it. */
function snapshot() {
  const vals = new Map<string, string | boolean>();
  for (const el of document.querySelectorAll<HTMLInputElement>('[data-keep]')) {
    vals.set(el.dataset.keep!, el.type === 'checkbox' ? el.checked : el.value);
  }
  const focused = (document.activeElement as HTMLElement | null)?.dataset?.keep;
  return () => {
    for (const el of document.querySelectorAll<HTMLInputElement>('[data-keep]')) {
      const v = vals.get(el.dataset.keep!);
      if (v === undefined) continue;
      if (el.type === 'checkbox') el.checked = v as boolean;
      else if (el.tagName !== 'SELECT' || [...(el as unknown as HTMLSelectElement).options].some((o) => o.value === v)) el.value = v as string;
    }
    if (focused) document.querySelector<HTMLElement>(`[data-keep="${focused}"]`)?.focus();
  };
}

function render() {
  const restore = snapshot();
  try {
    draw();
  } finally {
    restore();
  }
}

function draw() {
  $('my-name').textContent = a.profile.identity.find(me)?.name ?? '…';
  $('my-id').textContent = me.toHexString().slice(0, 10) + '…';
  const scopes = [...a.scope.iter()];
  // Jump to a workspace we just created, once its row arrives.
  const created = pendingSelect && scopes.find(pendingSelect);
  if (created) {
    current = created.id;
    tab = 'docs';
    pendingSelect = null;
  }
  if (current && !scopeOf(current)) current = 0n;
  if (!current && scopes.length) current = scopes.sort((x, y) => Number(x.id - y.id))[0].id;
  renderTree(scopes);
  renderMain();
}

function renderTree(scopes: ReturnType<typeof scopeOf>[]) {
  const tree = $('tree');
  tree.replaceChildren();
  const byParent = new Map<bigint, typeof scopes>();
  for (const s of scopes) {
    const key = s!.parent;
    byParent.set(key, [...(byParent.get(key) ?? []), s]);
  }
  const ids = new Set(scopes.map((s) => s!.id));
  const roots = scopes.filter((s) => !ids.has(s!.parent));
  const walk = (s: NonNullable<ReturnType<typeof scopeOf>>, depth: number) => {
    const b = h('button', { class: 'scope' + (s.id === current ? ' active' : ''), style: `padding-left:${10 + depth * 16}px`, onclick: () => ((current = s.id), render()) },
      svg(ICON[s.kind] ?? ICON.project), h('span', { class: 'grow' }, s.name));
    tree.append(b);
    for (const c of (byParent.get(s.id) ?? []).sort((x, y) => Number(x!.id - y!.id))) walk(c!, depth + 1);
  };
  for (const r of roots.sort((x, y) => Number(x!.id - y!.id))) walk(r!, 0);
  if (!roots.length) tree.append(h('div', { class: 'empty' }, 'None yet. Create one, or join with an invite.'));
}

function renderMain() {
  const main = $('main');
  main.replaceChildren();
  const s = scopeOf(current);
  if (!s) {
    main.append(
      h('div', { class: 'welcome' },
        h('h2', { class: 'title' }, 'Roles, scopes and grants'),
        h('p', { class: 'muted' }, 'Create a workspace and you become its admin. Add projects, invite people with a role, define your own roles, and watch what everyone can see change live. Docs are hidden by row-level security unless you hold doc.read.'))
    );
    return;
  }
  const crumbs = [...s.path].map((p) => scopeOf(p)?.name ?? '…');
  const perms = myPerms(s.id);
  const roles = myGrantsHere(s.id).map((g) => roleOf(g.roleId)?.name).filter(Boolean) as string[];
  main.append(
    h('div', { class: 'crumbs' }, [...crumbs, s.kind].join(' / ')),
    h('h2', { class: 'title' }, s.name),
    h('div', { class: 'chips' }, ...roles.map((r) => h('span', { class: 'chip role' }, r)), ...perms.map((p) => h('span', { class: 'chip' }, p)))
  );
  const tabs = h('div', { class: 'tabs' });
  for (const [k, label] of [['docs', 'Docs'], ['members', 'Members'], ['roles', 'Roles'], ['invites', 'Invites'], ['audit', 'Audit log']]) {
    tabs.append(h('button', { class: 'tab' + (tab === k ? ' active' : ''), onclick: () => ((tab = k), render()) }, label));
  }
  main.append(tabs);
  const body = h('div');
  main.append(body);
  ({ docs, members, roles: rolesTab, invites, audit } as Record<string, (s: any, el: HTMLElement) => void>)[tab](s, body);
}

function docs(s: NonNullable<ReturnType<typeof scopeOf>>, el: HTMLElement) {
  const list = [...a.doc.iter()].filter((d) => d.scopeId === s.id).sort((x, y) => Number(y.id - x.id));
  const card = h('div', { class: 'card' }, h('h3', {}, 'Docs'));
  if (!list.length) card.append(h('div', { class: 'muted' }, iCan('doc.read', s.id) ? 'No docs here yet.' : 'You can\'t read docs here (no doc.read), so row-level security hides them.'));
  for (const d of list) {
    card.append(
      h('div', { class: 'row' },
        h('div', { class: 'grow' }, h('strong', {}, d.title), h('div', { class: 'muted' }, d.body || '…'), h('div', { class: 'muted' }, `${nameOf(d.author)} · ${fmtTime(d.updatedAt)}`)),
        h('button', { class: 'btn small', onclick: () => call(a.deleteDoc(d.id), 'Deleted') }, 'Delete'))
    );
  }
  const title = h('input', { type: 'text', placeholder: 'Title', maxlength: 80, 'data-keep': 'doc-title' }) as HTMLInputElement;
  const text = h('textarea', { placeholder: 'Write something…', 'data-keep': 'doc-body' }) as HTMLTextAreaElement;
  const add = h('div', { class: 'card' }, h('h3', {}, 'New doc'), h('div', { class: 'form' }, title), text,
    h('div', { class: 'form' }, h('button', { class: 'btn primary', onclick: () => call(a.createDoc(s.id, title.value, text.value), 'Saved') }, 'Save'),
      h('span', { class: 'muted' }, iCan('doc.write', s.id) ? 'You hold doc.write here.' : 'Try it: you lack doc.write, so the module will refuse.')));
  const proj = h('input', { type: 'text', placeholder: 'Project name', maxlength: 64, 'data-keep': 'proj' }) as HTMLInputElement;
  const sub = h('div', { class: 'card' }, h('h3', {}, 'New project inside'), h('div', { class: 'form' }, proj,
    h('button', { class: 'btn', onclick: () => call(a.createScope(s.id, 'project', proj.value), 'Project created') }, 'Create')),
  h('div', { class: 'muted' }, 'Needs authz.scope.create. Grants on this scope reach the new project automatically.'));
  const danger = h('div', { class: 'card' }, h('h3', {}, 'Delete'), h('div', { class: 'form' },
    h('button', { class: 'btn', onclick: () => confirm(`Delete ${s.name} and everything in it?`) && call(a.deleteScope(s.id), 'Deleted') }, `Delete this ${s.kind}`),
    h('span', { class: 'muted' }, 'Needs authz.scope.delete.')));
  el.append(h('div', { class: 'grid2' }, card, h('div', {}, add, sub, danger)));
}

function members(s: NonNullable<ReturnType<typeof scopeOf>>, el: HTMLElement) {
  const chain = lineage(s.id);
  const grants = [...a.grant.iter()].filter((g) => chain.includes(g.scopeId)).sort((x, y) => Number(x.id - y.id));
  const card = h('div', { class: 'card' }, h('h3', {}, 'Who has access here'));
  for (const g of grants) {
    const where = g.scopeId === s.id ? 'here' : g.scopeId === 0n ? 'everywhere' : `from ${scopeOf(g.scopeId)?.name ?? '…'}`;
    const exp = g.expiresAt ? ` · until ${fmtTime(g.expiresAt)}` : '';
    card.append(
      h('div', { class: 'row' },
        h('div', { class: 'grow' }, h('strong', {}, nameOf(g.identity)), ' ', h('span', { class: 'chip role' }, roleOf(g.roleId)?.name ?? '?'), h('div', { class: 'muted' }, `${where}${exp}`)),
        h('button', { class: 'btn small', onclick: () => call(a.revokeGrant(g.id), g.identity.isEqual(me) ? 'You left' : 'Revoked') }, g.identity.isEqual(me) ? 'Leave' : 'Revoke'))
    );
  }
  const people = h('select', { 'data-keep': 'g-who' }, ...[...a.profile.iter()].filter((p) => !p.identity.isEqual(me)).map((p) => h('option', { value: p.identity.toHexString() }, p.name))) as HTMLSelectElement;
  const role = h('select', { 'data-keep': 'g-role' }, ...usableRoles(s.id).map((r) => h('option', { value: r.id.toString() }, r.name))) as HTMLSelectElement;
  const exp = h('select', { 'data-keep': 'g-exp' }, h('option', { value: '0' }, 'forever'), h('option', { value: '60' }, 'for 1 minute'), h('option', { value: '3600' }, 'for 1 hour'), h('option', { value: '86400' }, 'for 1 day')) as HTMLSelectElement;
  const grant = h('div', { class: 'card' }, h('h3', {}, 'Grant a role here'), h('div', { class: 'form' }, people, role, exp,
    h('button', { class: 'btn primary', onclick: () => {
      const who = [...a.profile.iter()].find((p) => p.identity.toHexString() === people.value)?.identity;
      if (!who) return toast('Pick someone', true);
      const secs = Number(exp.value);
      call(a.grantRole(who, BigInt(role.value), s.id, secs ? inSecs(secs) : undefined), 'Granted');
    } }, 'Grant')),
  h('p', { class: 'muted' }, 'Needs authz.grant, and you can only hand out roles whose permissions you hold yourself.'));
  el.append(h('div', { class: 'grid2' }, card, grant));
}

function rolesTab(s: NonNullable<ReturnType<typeof scopeOf>>, el: HTMLElement) {
  const card = h('div', { class: 'card' }, h('h3', {}, 'Roles available here'));
  for (const r of usableRoles(s.id)) {
    const from = r.scopeId === 0n ? 'global' : `defined in ${scopeOf(r.scopeId)?.name ?? '…'}`;
    card.append(
      h('div', { class: 'row' },
        h('div', { class: 'grow' }, h('strong', {}, r.name), h('span', { class: 'muted' }, ` · ${from}${r.system ? ' · system' : ''}`),
          h('div', { class: 'chips' }, ...[...r.effective].map((p) => h('span', { class: 'chip' }, p)))),
        r.system ? null : h('button', { class: 'btn small', onclick: () => call(a.deleteRole(r.id), 'Role deleted') }, 'Delete'))
    );
  }
  const name = h('input', { type: 'text', placeholder: 'Role name', maxlength: 64, 'data-keep': 'r-name' }) as HTMLInputElement;
  const boxes = PERMS.map((p) => h('input', { type: 'checkbox', value: p, 'data-keep': `r-${p}` }) as HTMLInputElement);
  const inherit = h('select', { 'data-keep': 'r-inherit' }, h('option', { value: '' }, 'inherits nothing'), ...usableRoles(s.id).map((r) => h('option', { value: r.id.toString() }, `inherits ${r.name}`))) as HTMLSelectElement;
  const make = h('div', { class: 'card' }, h('h3', {}, `New role in ${s.name}`), h('div', { class: 'form' }, name, inherit),
    h('div', { class: 'perms' }, ...boxes.map((b) => h('label', {}, b, b.value))),
    h('button', { class: 'btn primary', onclick: () => call(a.createRole(s.id, name.value, boxes.filter((b) => b.checked).map((b) => b.value), inherit.value ? [BigInt(inherit.value)] : []), 'Role created') }, 'Create role'),
    h('p', { class: 'muted' }, 'Needs authz.role, and only permissions you hold. The role is usable in this scope and below.'));
  el.append(h('div', { class: 'grid2' }, card, make));
}

function invites(s: NonNullable<ReturnType<typeof scopeOf>>, el: HTMLElement) {
  const list = [...a.invite.iter()].filter((i) => i.scopeId === s.id);
  const card = h('div', { class: 'card' }, h('h3', {}, 'Open invites'));
  if (!list.length) card.append(h('div', { class: 'muted' }, iCan('authz.invite', s.id) ? 'None.' : 'You need authz.invite to see and create invites here.'));
  for (const i of list) {
    const uses = i.maxUses ? `${i.uses}/${i.maxUses} used` : `${i.uses} used`;
    card.append(h('div', { class: 'row' },
      h('div', { class: 'grow' }, h('span', { class: 'chip role' }, roleOf(i.roleId)?.name ?? '?'), h('div', { class: 'muted' }, `${uses} · by ${nameOf(i.createdBy)}${i.expiresAt ? ` · until ${fmtTime(i.expiresAt)}` : ''}`)),
      h('button', { class: 'btn small', onclick: () => call(a.revokeInvite(i.id), 'Invite revoked') }, 'Revoke')));
  }
  const role = h('select', { 'data-keep': 'i-role' }, ...usableRoles(s.id).map((r) => h('option', { value: r.id.toString() }, r.name))) as HTMLSelectElement;
  const uses = h('select', { 'data-keep': 'i-uses' }, h('option', { value: '1' }, '1 use'), h('option', { value: '5' }, '5 uses'), h('option', { value: '0' }, 'unlimited')) as HTMLSelectElement;
  const exp = h('select', { 'data-keep': 'i-exp' }, h('option', { value: '86400' }, 'expires in a day'), h('option', { value: '3600' }, 'in an hour'), h('option', { value: '0' }, 'never expires')) as HTMLSelectElement;
  const out = h('div', { class: 'link mono' }, lastInvite);
  const make = h('div', { class: 'card' }, h('h3', {}, 'Invite someone'), h('div', { class: 'form' }, role, uses, exp,
    h('button', { class: 'btn primary', onclick: async () => {
      const code = randomCode();
      const secs = Number(exp.value);
      if (await call(a.createInvite(code, BigInt(role.value), s.id, Number(uses.value), secs ? inSecs(secs) : undefined, 0n), 'Invite created')) {
        const url = new URL(location.href);
        url.searchParams.set('invite', code);
        url.searchParams.delete('fresh');
        lastInvite = url.toString();
        render();
      }
    } }, 'Create link')), out,
  h('p', { class: 'muted' }, 'The code is generated in your browser and stored privately; others only ever see the invite\'s metadata.'));
  el.append(h('div', { class: 'grid2' }, card, make));
}

function audit(s: NonNullable<ReturnType<typeof scopeOf>>, el: HTMLElement) {
  const ids = new Set([s.id, ...[...a.scope.iter()].filter((x) => x.path.includes(s.id)).map((x) => x.id)]);
  const rows = [...a.audit.iter()].filter((x) => ids.has(x.scopeId)).sort((x, y) => Number(y.id - x.id)).slice(0, 100);
  if (!rows.length) {
    el.append(h('div', { class: 'card muted' }, iCan('authz.audit', s.id) ? 'Nothing yet.' : 'You need authz.audit to see the log.'));
    return;
  }
  const t = h('table', {}, h('tr', {}, ...['When', 'Who', 'What', 'Whom', 'Role', 'Where'].map((x) => h('th', {}, x))));
  const zero = (id: Identity) => /^0+$/.test(id.toHexString().replace(/^0x/, ''));
  for (const r of rows) {
    t.append(h('tr', {},
      h('td', {}, fmtTime(r.at)), h('td', {}, r.actor ? nameOf(r.actor) : 'module'), h('td', {}, r.action + (r.detail ? ` ${r.detail}` : '')),
      h('td', {}, zero(r.target) ? '' : nameOf(r.target)), h('td', {}, r.roleId ? roleOf(r.roleId)?.name ?? `#${r.roleId}` : ''), h('td', {}, scopeOf(r.scopeId)?.name ?? '')));
  }
  el.append(h('div', { class: 'card' }, t));
}

// -- controls --------------------------------------------------------------------------

$('new-ws').onsubmit = (e) => {
  e.preventDefault();
  const name = $<HTMLInputElement>('new-ws-name').value;
  const known = new Set([...a.scope.iter()].map((s) => s.id));
  pendingSelect = (s) => s.name === name && !known.has(s.id);
  call(a.createWorkspace(name), 'Workspace created').then((ok) => {
    if (ok) $<HTMLInputElement>('new-ws-name').value = '';
    else pendingSelect = null;
  });
};
$('redeem').onsubmit = (e) => {
  e.preventDefault();
  const raw = $<HTMLInputElement>('redeem-code').value.trim();
  const code = raw.includes('invite=') ? new URL(raw).searchParams.get('invite') ?? raw : raw;
  call(a.redeemInvite(code), 'Invite accepted').then((ok) => ok && ($<HTMLInputElement>('redeem-code').value = ''));
};
$('my-name').onclick = () => {
  const name = prompt('Your name', a.profile.identity.find(me)?.name ?? '');
  if (name) call(a.setName(name));
};
$('my-id').onclick = () => navigator.clipboard?.writeText(me.toHexString()).then(() => toast('Identity copied'));
setInterval(queue, 5000); // expiry labels
render();
