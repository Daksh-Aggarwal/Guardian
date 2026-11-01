# Guardian accounts, CLI login and deployment

Guardian now connects the existing local scanner to a Supabase account. The website uses the official Supabase JavaScript SDK with GitHub OAuth/PKCE; the API verifies the access token independently. CLI reports synchronize only after `guardian sync` or `guardian report --sync`. Local scans and installation policy do not depend on login.

## Configuration in `.env`

The repository's ignored `.env` is the local source of configuration for Next.js, the Python API and the editable CLI. Existing values are preserved; fill the newly added empty settings yourself. `.env.example` contains placeholders only. Environment variables supplied by a host or shell take precedence. Next.js also gives `.env.local` precedence over `.env`; remove conflicting overrides when testing changes. Restart Python and rebuild/restart Next.js after edits. Installed CLI users outside this checkout should export the CLI variables in their shell; Guardian never loads an analyzed project's `.env`.

| Variable | Where | Value |
| --- | --- | --- |
| `NEXT_PUBLIC_SUPABASE_URL` | Frontend/local API fallback | Supabase Project Settings → API → Project URL, no trailing path |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | Frontend/local API fallback | Publishable key (`sb_publishable_…`), or legacy **anon** key; never a secret/service-role key |
| `SUPABASE_URL` | API | Optional local override of the public URL; set explicitly on Render |
| `SUPABASE_PUBLISHABLE_KEY` | API | Optional local override of the public key; set explicitly on Render |
| `GUARDIAN_DATABASE_URL` | API only | Supabase PostgreSQL/pooler connection string, password URL-encoded, `sslmode=require` |
| `GUARDIAN_ACCOUNT_STORE` | Local API | `sqlite` explicitly allows account development in the existing `GUARDIAN_DB`; unused when PostgreSQL URL is present and forbidden in cloud mode |
| `GUARDIAN_API_URL` | Next.js and CLI | API origin. Local: `http://127.0.0.1:8000`. Deployment: actual HTTPS Render origin. Next.js proxies `/api/*` here. CLI must use the same API as the website. |
| `GUARDIAN_FRONTEND_URL` | API | Local `http://127.0.0.1:3000`; deployed Vercel HTTPS origin; used for CLI browser opening |
| `GUARDIAN_PUBLIC_API_URL` | API | Local `http://127.0.0.1:8000`; actual Render HTTPS origin; used for the Supabase CLI callback |
| `GUARDIAN_ALLOWED_ORIGINS` | API | Comma-separated exact frontend origins. Local defaults include localhost and 127.0.0.1:3000. Production: actual Vercel origin, no wildcard. |
| `GUARDIAN_CLOUD_MODE` | Next.js/API | Local `false`; deployed **true on both services**. Root redirects to `/account`; public API permits account routes and health only. |
| `GUARDIAN_ALLOW_FILE_CREDENTIALS` | CLI | Default `false`. Explicit persistent opt-in to private plaintext fallback; prefer the one-time login flag below. |
| `GUARDIAN_HOME` | CLI, optional | Private state directory; default `~/.local/state/guardian` (Unix/XDG) or `%LOCALAPPDATA%/Guardian` (Windows) |
| `GUARDIAN_DB` | Local API | Existing local SQLite path, default unchanged |
| `PORT` | Render only | Provided by Render; startup binds `0.0.0.0:$PORT` only in explicit cloud mode |

No Supabase service-role key or JWT signing secret is needed. JWTs use configured issuer `/auth/v1`, authenticated audience/role, expiry, UUID subject/session and RS256/ES256 JWKS signature validation. Legacy HS256 tokens are validated against Supabase `/auth/v1/user`, then checked for issuer/audience/expiry and matching subject. Failed key/Auth lookups fail visibly. Never put database credentials, GitHub OAuth secrets or signing keys in `NEXT_PUBLIC_*` variables.

## Supabase dashboard setup

1. Create/select your Supabase project. Copy its URL and publishable key to `.env` above.
2. In GitHub **Settings → Developer settings → OAuth Apps → New OAuth App**, create a separate OAuth application for human Guardian accounts. Homepage is your actual frontend origin. Authorization callback is **`https://<your-project-ref>.supabase.co/auth/v1/callback`** (use your Supabase custom Auth domain instead if configured). This is not the Guardian GitHub App's callback.
3. Supabase **Authentication → Sign In / Providers → GitHub**: enable GitHub and enter that OAuth App's client ID and secret. Keep the secret in this provider dashboard, not the frontend or CLI. A development Supabase project can use a separate GitHub OAuth App with its own Supabase callback.
4. Supabase **Authentication → URL Configuration**: set Site URL to the actual Vercel frontend origin. Add these redirect URLs, replacing placeholders with actual origins:
   - `https://<frontend>/auth/callback`
   - `https://<render-api>/api/account/cli/callback/*`
   - For development: `http://127.0.0.1:3000/auth/callback` and `http://127.0.0.1:8000/api/account/cli/callback/*`. Add localhost equivalents only if you actually use them consistently.
5. Do not add arbitrary external redirects or a broad global wildcard. The CLI's random loopback port is handled by Guardian's backend after Supabase redirects to its fixed callback prefix; Supabase does not need a random-port redirect rule.
6. Leave Supabase session refresh enabled. New asymmetric signing keys are recommended; legacy HS256 works through online Auth validation. Never copy the signing secret into the client.

Official references: [GitHub provider setup](https://supabase.com/docs/guides/auth/social-sign-in/auth-github), [PKCE](https://supabase.com/docs/guides/auth/sessions/pkce-flow), [JWT verification](https://supabase.com/docs/guides/auth/jwts).

## Database migration

Open Supabase **SQL Editor**, paste and run [`supabase/migrations/202611010001_guardian_accounts.sql`](../supabase/migrations/202611010001_guardian_accounts.sql) once as the project database owner. It is transaction-wrapped and rerunnable. It creates prefixed account/profile, device, scan, revoked-session and short-lived CLI authorization tables in the same Supabase database. Existing local scan/GitHub tables are unchanged.

In Supabase **Connect**, copy the PostgreSQL **Session pooler** connection string (IPv4-friendly). Replace the password placeholder, URL-encode reserved characters, append `?sslmode=require` if the URL has no query, or `&sslmode=require` otherwise. Put it in `GUARDIAN_DATABASE_URL` on the API only. Transaction pooling is also supported: psycopg prepared statements are disabled (`prepare_threshold=None`). The backend uses a privileged server-side PostgreSQL connection and enforces user ownership in every query. RLS provides owner-only direct SELECT for profiles/scans; browser writes, device session bindings, revoked sessions and authorization records are denied. Do not weaken these grants to solve configuration errors.

For local development without PostgreSQL, leave the URL blank and set `GUARDIAN_ACCOUNT_STORE=sqlite`. This explicitly reuses the existing local database, creating the account tables automatically. It is a development fallback, not a cloud database substitute.

## Local setup

Use Node **22+** (tested on 26) for the current Supabase SDK and Python 3.9+ locally. Render pins Python 3.12.8.

```sh
npm ci --ignore-scripts
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
.venv/bin/pip install --no-deps -e .
# Fill the account settings in .env first.
.venv/bin/python scripts/serve_api.py
# In another terminal:
npm run dev
```

Open `http://127.0.0.1:3000/account`. Use the same hostname throughout a PKCE login; verifier/session storage belongs to that browser origin. The API health endpoint `/api/health` checks process liveness. Protected `/api/account/me` additionally exercises JWT verification and database access. Missing account settings return actionable 503 errors while local scans continue.

## Render API deployment

1. Push the reviewed code to your Git repository, then Render **New → Blueprint** and select this repository's `render.yaml` (or create a Python Web Service with the same commands).
2. Root directory: repository root. Build: `pip install -r backend/requirements.txt`. Start: `python scripts/serve_api.py`. Health check: `/api/health`. Runtime: Python 3.12.8. Keep one service instance for this sprint's in-process login rate limiter.
3. Fill Blueprint `sync:false` variables in Render's environment editor: `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `GUARDIAN_DATABASE_URL`, `GUARDIAN_FRONTEND_URL`, `GUARDIAN_PUBLIC_API_URL`, `GUARDIAN_ALLOWED_ORIGINS`. Use the actual assigned frontend/API HTTPS domains. `GUARDIAN_CLOUD_MODE=true` is already set by the Blueprint.
4. Apply the migration before the first account request. The start script rejects missing basic cloud configuration. Do not enable SQLite fallback in production. Render's local filesystem is not used for account persistence.
5. Deploy. Check `/api/health` returns 200; then sign in and verify `/api/account/me` through the website. An unauthenticated `/api/account/scans` must return 401 and `/api/scans` must return 403 in cloud mode.
6. Keep OAuth callback query strings out of logs/analytics. The supplied startup command disables Uvicorn access logs; configure any additional proxy/request logging to omit query strings too.

No Node runtime is needed on the account-only Render API: it does not scan cloud source or execute packages. Source analysis stays local.

## Vercel frontend deployment

1. Vercel **Add New → Project → Import Git Repository**. Framework: **Next.js**. Root: repository root. Install: `npm ci --ignore-scripts`. Build: `npm run build`. Output directory: Next.js default (do not select a static export). Node version **22 or later**.
2. Add `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `GUARDIAN_API_URL=https://<actual-render-api>` and `GUARDIAN_CLOUD_MODE=true` in project environment settings for Production (and separately for Preview only if you configure its redirects/origins).
3. Deploy, then set Render's frontend/CORS variables and Supabase Site URL/redirect allowlist to the real Vercel domain. Redeploy either service after changing its environment. `NEXT_PUBLIC_*` and the Next rewrite/root redirect are captured at build time.
4. Open the deployment: `/` redirects to `/account`; sign in with GitHub. The browser uses same-origin `/api/account/*` through the existing Next.js rewrite. Never put the PostgreSQL URL or GitHub App secrets on Vercel's public variable list.
5. Log out, reload, log back in, and test a second account cannot see the first account's reports/devices. No extra `vercel.json` is required.

Provider dashboards do not read your laptop's `.env`: copy the appropriate values into their environment editors. Keep `.env` ignored and local.

## Exact demonstration

After configuration, open the website and sign in with GitHub. For a deployed demo, set `GUARDIAN_API_URL` in `.env` to the same Render API used by Vercel, then restart the CLI process. Keep local API/frontend URLs only for local demo.

```sh
.venv/bin/guardian login
.venv/bin/guardian status
.venv/bin/guardian devices
.venv/bin/guardian check --ecosystem npm lodash@4.17.21
.venv/bin/guardian report
.venv/bin/guardian report --sync
# Upload any other eligible unsynced saved CLI reports:
.venv/bin/guardian sync
```

A `check` exit code 3/REVIEW is expected if coverage is incomplete; continue to `report --sync` in a separate command. Do not weaken policy for the demo. Return to `/account` and press **Refresh**. Inspect the actual device and report, preserved decision, findings, dependency artifacts and coverage notices. Revoke the CLI device in the dashboard, then `guardian status`/a new sync must refuse its authorization. Reconnect using `guardian login`. Run `guardian logout` to remove local credentials and revoke the Guardian device remotely.

OS credential storage is the default (macOS Keychain, Windows Credential Manager, Secret Service/KWallet when available). If no supported, usable manager exists, explicitly use `guardian login --allow-file-credentials`; it warns and writes tokens atomically to private files (0600) in the state directory (created 0700). This is plaintext, not encrypted. Existing permissive files and symbolic links are rejected. Never commit or share that directory. After file fallback was explicitly selected, later processes can read it without repeating the flag. A locked/refusing keychain requires unlocking it or explicitly selecting the file fallback with the flag. That flag selects private-file storage even when a keychain backend is installed; no automatic silent downgrade occurs. To switch Guardian accounts on one installation, log out first, then `guardian login --new-device`. Metadata retains a stable random device UUID across normal logins.

`--no-browser` prints a short-lived Guardian URL to open manually on the same machine. No password, GitHub token or Supabase token is pasted into the terminal. If logout is offline, local credentials are still removed; the command reports that remote revocation must be completed on the website.

## Flow and safety boundaries

The CLI creates random S256 PKCE and state, binds an ephemeral **127.0.0.1** callback server, and requests a five-minute authorization record. Guardian shows an explicit device approval page, then redirects to Supabase's standard GitHub PKCE authorization. Supabase returns its code to Guardian's configured backend callback. That backend stores only the code hash and returns the original single-use code plus the original CLI state to the validated loopback URI. CLI validates state/Host/path and exchanges code+verifier through Guardian. Guardian checks state, S256 challenge, code hash and atomic single consumption, exchanges with Supabase, independently verifies the returned JWT, then registers the device. Refresh tokens are returned over HTTPS to the credential store; they are not stored in the account database or URLs. Device revocation also blocks its Supabase session ID at the Guardian API, so an unexpired old access token cannot simply register a new device.

Uploads require explicit consent, a verified user/session and an active device bound to that session. Payloads are capped before JSON parsing and validated against the existing Report model. `(user_id, report_id)` is immutable/idempotent; identical retries return the existing report and changed evidence under the same ID returns 409. The CLI sync ledger is written only after success. Failed uploads never change/delete local reports.

The sync adapter withholds evidence/data-flow **source snippets**, drops flexible arbitrary payload fields, redacts recognized credential patterns and preserves finding IDs, file/line evidence locations, decision, hashes, dependency graph, coverage and limitations. It adds an explicit notice that submitted evidence was not independently rescanned. Redaction is pattern-based; do not treat it as proof that arbitrary free text contains no sensitive material. No archives, complete source trees or project handles are sent. Cloud Handoff exports reuse the sanitized report, with ownership enforcement.

**Public deployment limitation:** `GUARDIAN_CLOUD_MODE=true` serves accounts/devices/report sync and health only. Existing local upload, scanning, filesystem remediation, Intelligence and GitHub App workspace routes remain available in the local service, with existing session isolation. They are intentionally unavailable on the public account service because those local SQLite routes were not designed for multi-user account ownership. The deployed dashboard displays reports and Handoff; investigation/remediation requires local Guardian. Supabase human OAuth does not grant access to any GitHub App installation. No installation endpoint, permission model or session table was replaced.

## Verification

```sh
.venv/bin/python -m pytest backend/tests -q
npm test
npm run typecheck
npm run build
git diff --check
# Optional, with local PostgreSQL initdb/pg_ctl available:
.venv/bin/python scripts/test_account_postgres.py
```

The new tests validate real RSA JWT signatures, expiry/malformed/wrong claims, bounded JWKS retrieval, legacy Auth validation, unauthorized/cross-user requests, devices/revocation, report retry/immutability/sanitization, PKCE/state/replay/expiry, a real loopback callback, CLI-to-API login/sync/retrieval/logout, private-file/keyring adapters, refresh rotation and failure without report loss. Provider Auth responses, OS keyring entries and browser opening are mocked. Frontend tests exercise actual Supabase SDK session persistence/restoration/events/logout and authenticated request refresh/error handling with mocked transport. PostgreSQL check creates/removes a private temporary local cluster and validates the actual migration, JSONB persistence and RLS; it never uses your Supabase project.

These tests are not live GitHub OAuth or hosted deployment verification. Complete the demo above after entering real settings; no deployment URLs or successful provider handshakes are fabricated.

## Implementation map and measured results

- Website: `app/account/page.tsx`, `app/auth/{callback,cli}/page.tsx`, `app/account.css`, `components/account-{provider,dashboard}.tsx`, `lib/{supabase,account-request}.ts`; small integration changes in `app/{layout,page}.tsx`, `components/{report,handoff-modal}.tsx` and `next.config.ts`.
- API and persistence: `backend/guardian/{account_auth,account_api,account_store,report_sync,environment}.py`, account router/CORS/public-service boundary in `main.py`, capabilities in `cli_bridge.py`, and the Supabase migration.
- CLI: `backend/guardian/{connected,credential_store}.py`, account commands in `cli.py`; existing scanner/installer adapters stay unchanged by this sprint.
- Setup: ignored `.env`, `.env.example`, `render.yaml`, `scripts/serve_api.py`, Python/npm manifests, README and CLI documentation.
- Checks: `backend/tests/{test_accounts,test_connected}.py`, isolated test environment in `conftest.py`, updated offline account expectation in `test_cli.py`, `scripts/{test_account.mjs,test_account_postgres.py}`.

November 1, 2026: full backend suite **481 passed**; frontend suite **40 passed** (29 filesystem, 6 Handoff, 5 account); strict TypeScript and local/cloud-mode production builds passed; real temporary PostgreSQL migration/API/RLS check passed. Browser inspection verified the logged-out/configuration state and cloud root redirect. No separate lint script exists. Existing Python/OpenSSL/deprecation and Node module warnings remain. Live GitHub OAuth, native OS keychain interaction, actual Supabase-hosted PostgreSQL and Vercel/Render deployments have **not** been verified; provider settings and credentials are intentionally left for you to fill.

## Troubleshooting `guardian login` setup errors

A nonempty `GUARDIAN_DATABASE_URL` always selects PostgreSQL, even when `GUARDIAN_ACCOUNT_STORE=sqlite` is also set. Supabase's copied URL contains a password placeholder until you replace it. Enter your actual **database password**, URL-encoded, in the ignored Guardian `.env` and restart the API. Prefer the dashboard's Session pooler URL and `sslmode=require`; apply the account migration through the SQL Editor. Do not use an anon/publishable key as the database password or paste the connection string into chat.

For local account development without PostgreSQL, explicitly leave `GUARDIAN_DATABASE_URL=` empty and keep `GUARDIAN_ACCOUNT_STORE=sqlite`. Restart the API after changing `.env`; an existing process retains its earlier configuration. This local mode does not share storage with a deployed dashboard.

The API labels known configuration failures with safe error codes; the CLI translates those codes into actionable messages. It never prints arbitrary server response text, PostgreSQL exception details, passwords or connection strings. Placeholder passwords are rejected before attempting a database connection.
