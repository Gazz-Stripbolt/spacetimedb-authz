# Demo: a team workspace

Anyone can create a **workspace** and becomes its admin. Inside it:
- add **projects** (child scopes)
- write **docs**, which are hidden by row-level security from anyone without `doc.read` there
- **grant** roles with optional expiry
- define **custom roles** from the permissions you hold
- create **invite links**
- read the **audit log**

Try being the guest: an invite link makes you a viewer, and the module refuses your edits. Grant yourself editor from
another window and they work.

The same demo exists in Rust, C# and TypeScript. They share one web page ([`web/`](web)), which each module serves
from its own HTTP route.

```bash
npm install && npm run build:web          # bundles web/ into web/dist/index.html
spacetime start                           # in another terminal
spacetime publish -s local authz -p demo/rust     # or demo/csharp, demo/typescript
open http://127.0.0.1:3000/v1/database/authz/route/
```

Open it in two browser windows (or a private window) to be two people. For a hosted copy of `web/dist/index.html`,
pass `?host=wss://…&db=<name>` (add `&flavor=ns` for the TypeScript module).

`scripts/e2e.sh rust|csharp|typescript` publishes a demo and runs the protocol tests, the page test and the
permission-check benchmark against it.
