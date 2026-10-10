#!/usr/bin/env bash
# Publish a demo module and run the protocol tests, the page test and the check benchmark.
#
#   scripts/e2e.sh rust|csharp|typescript      (needs a local server: `spacetime start`)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LANG_=${1:?usage: $0 rust|csharp|typescript}
SERVER=${SERVER:-local}
HTTP=${HTTP:-http://127.0.0.1:3000}
DB=${DB:-authz-$LANG_}
FLAVOR=flat
[[ $LANG_ == typescript ]] && FLAVOR=ns

cd "$ROOT"
npm run build -w typescript --silent >/dev/null   # the demos import the packages' compiled dist/
[[ -f demo/web/dist/index.html && -f demo/typescript/src/page.gen.ts ]] || node demo/web/build.mjs
echo "== publish demo/$LANG_ as $DB"
spacetime publish -s "$SERVER" -y "$DB" -p "demo/$LANG_" --delete-data >/dev/null
echo "== protocol tests ($FLAVOR schema)"
DB=$DB FLAVOR=$FLAVOR SERVER=$SERVER HOST=${HTTP/http/ws} npx tsx tests/server.test.mts 2>&1 | grep -v 'INFO Connecting'
echo "== page test"
PAGE="$HTTP/v1/database/$DB/route/" npx tsx tests/page.test.mts 2>&1 | grep -v 'INFO Connecting'
echo "== permission-check benchmark"
DB=$DB FLAVOR=$FLAVOR HOST=${HTTP/http/ws} npx tsx tests/bench.mts 2>&1 | grep -v 'INFO Connecting'
