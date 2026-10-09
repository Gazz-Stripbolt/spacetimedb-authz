// Permission-check throughput: time `demo_bench(scope, n)`, which runs n `can()` checks inside one
// reducer (half allowed, half denied), against a 3-level scope tree with a few grants on the path.
//
//   DB=authz-rust [FLAVOR=flat|ns] N=200000 npx tsx tests/bench.mts
import { connect, type Flavor } from '../demo/web/src/api.ts';

const HOST = process.env.HOST ?? 'ws://127.0.0.1:3000';
const DB = process.env.DB ?? 'authz-rust';
const FLAVOR = (process.env.FLAVOR ?? 'flat') as Flavor;
const N = Number(process.env.N ?? 200_000);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const a = await connect(FLAVOR, HOST, DB);
await a.subscribeAll();
const name = `bench-${Date.now()}`;
await a.createWorkspace(name);
await sleep(150);
const W = [...a.scope.iter()].find((s) => s.name === name)!.id;
await a.createScope(W, 'project', `${name}-p`);
await sleep(150);
const P = [...a.scope.iter()].find((s) => s.name === `${name}-p`)!.id;
await a.createScope(P, 'folder', `${name}-f`);
await sleep(150);
const F = [...a.scope.iter()].find((s) => s.name === `${name}-f`)!.id;
// A few extra grants for the caller on the path, so checks walk real data.
const viewer = [...a.role.iter()].find((r) => r.name === 'viewer' && r.scopeId === 0n)!.id;
await a.grantRole(a.identity, viewer, P);
await a.grantRole(a.identity, viewer, F);

async function time(n: number) {
  const t0 = performance.now();
  await a.bench(F, n);
  return performance.now() - t0;
}
await time(1000); // warm up
const base = Math.min(await time(0), await time(0), await time(0));
const runs = [await time(N), await time(N), await time(N)];
const best = Math.min(...runs) - base;
console.log(`${DB}: ${N} checks (3-level scope, grants at 3 levels) in ${best.toFixed(1)} ms → ${((N / best) * 1000 / 1e6).toFixed(2)} M checks/s (${((best * 1e6) / N).toFixed(0)} ns each)`);
await a.deleteScope(W);
a.conn.disconnect();
process.exit(0);
